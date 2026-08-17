#include "async_bof_patch.h"
#include <string.h>
#include <stdio.h>

DWORD async_coff_get_section_count(PBYTE pCoffData, DWORD dwCoffSize) {
    if (!pCoffData || dwCoffSize < sizeof(COFF_HEADER)) {
        return 0;
    }
    PCOFF_HEADER pHeader = (PCOFF_HEADER)pCoffData;
    return pHeader->NumberOfSections;
}

PCOFF_SECTION async_coff_get_section(PBYTE pCoffData, DWORD dwCoffSize, DWORD dwSectionIndex) {
    if (!pCoffData || dwCoffSize < sizeof(COFF_HEADER)) {
        return NULL;
    }

    PCOFF_HEADER pHeader = (PCOFF_HEADER)pCoffData;
    DWORD dwSectionCount = pHeader->NumberOfSections;

    if (dwSectionIndex >= dwSectionCount) {
        return NULL;
    }

    DWORD dwOptHeaderSize = pHeader->SizeOfOptionalHeader;
    PBYTE pSectionTable = pCoffData + sizeof(COFF_HEADER) + dwOptHeaderSize;

    DWORD dwSectionSize = sizeof(COFF_SECTION);
    DWORD dwOffset = dwSectionIndex * dwSectionSize;

    if (sizeof(COFF_HEADER) + dwOptHeaderSize + dwOffset + dwSectionSize > dwCoffSize) {
        return NULL;
    }

    return (PCOFF_SECTION)(pSectionTable + dwOffset);
}

PCOFF_SECTION async_coff_find_section(PBYTE pCoffData, DWORD dwCoffSize, PCSTR pszSectionName) {
    if (!pCoffData || dwCoffSize < sizeof(COFF_HEADER) || !pszSectionName) {
        return NULL;
    }

    PCOFF_HEADER pHeader = (PCOFF_HEADER)pCoffData;
    DWORD dwSectionCount = pHeader->NumberOfSections;
    DWORD dwOptHeaderSize = pHeader->SizeOfOptionalHeader;

    if ((ULONG_PTR)sizeof(COFF_HEADER) + dwOptHeaderSize
            + (ULONG_PTR)dwSectionCount * sizeof(COFF_SECTION) > dwCoffSize) {
        return NULL;
    }

    PBYTE pSectionTable = pCoffData + sizeof(COFF_HEADER) + dwOptHeaderSize;

    for (DWORD i = 0; i < dwSectionCount; i++) {
        PCOFF_SECTION pSection = (PCOFF_SECTION)(pSectionTable + i * sizeof(COFF_SECTION));
        if (strncmp(pSection->Name, pszSectionName, 8) == 0) {
            return pSection;
        }
    }

    return NULL;
}

PCOFF_SECTION async_coff_get_sections(PBYTE pCoffData, DWORD dwCoffSize, PDWORD pdwSectionCount) {
    if (!pCoffData || dwCoffSize < sizeof(COFF_HEADER) || !pdwSectionCount) {
        return NULL;
    }

    PCOFF_HEADER pHeader = (PCOFF_HEADER)pCoffData;
    DWORD dwSectionCount = pHeader->NumberOfSections;
    DWORD dwOptHeaderSize = pHeader->SizeOfOptionalHeader;

    if ((ULONG_PTR)sizeof(COFF_HEADER) + dwOptHeaderSize
            + (ULONG_PTR)dwSectionCount * sizeof(COFF_SECTION) > dwCoffSize) {
        *pdwSectionCount = 0;
        return NULL;
    }

    *pdwSectionCount = dwSectionCount;
    return (PCOFF_SECTION)(pCoffData + sizeof(COFF_HEADER) + dwOptHeaderSize);
}

DWORD async_coff_get_relocation_count(PCOFF_SECTION pSection) {
    if (!pSection) {
        return 0;
    }
    return pSection->NumberOfRelocations;
}

PCOFF_RELOCATION async_coff_get_relocation(PBYTE pCoffData, DWORD dwCoffSize, PCOFF_SECTION pSection, DWORD dwRelocIndex) {
    if (!pCoffData || !pSection || dwRelocIndex >= pSection->NumberOfRelocations) {
        return NULL;
    }

    if (pSection->PointerToRelocations == 0) {
        return NULL;
    }

    DWORD dwOffset = pSection->PointerToRelocations + dwRelocIndex * sizeof(COFF_RELOCATION);
    if (dwOffset + sizeof(COFF_RELOCATION) > dwCoffSize) {
        return NULL;
    }

    return (PCOFF_RELOCATION)(pCoffData + dwOffset);
}

static void async_coff_get_string_at_offset(PBYTE pCoffData, DWORD dwCoffSize, DWORD dwOffset, char* outBuf, DWORD dwBufSize) {
    if (!pCoffData || !outBuf || dwBufSize == 0) {
        return;
    }

    if (dwOffset >= dwCoffSize) {
        outBuf[0] = '\0';
        return;
    }

    DWORD dwMaxLen = dwCoffSize - dwOffset;
    DWORD dwCopyLen = (dwMaxLen < dwBufSize - 1) ? dwMaxLen : dwBufSize - 1;

    memcpy(outBuf, pCoffData + dwOffset, dwCopyLen);
    outBuf[dwCopyLen] = '\0';
}

PCSTR async_coff_get_symbol_name(PBYTE pCoffData, DWORD dwCoffSize, DWORD dwSymbolIndex) {
    static char s_szNameBuf[256];

    if (!pCoffData || dwCoffSize < sizeof(COFF_HEADER)) {
        return NULL;
    }

    PCOFF_HEADER pHeader = (PCOFF_HEADER)pCoffData;
    PBYTE pSymbolTable = pCoffData + pHeader->PointerToSymbolTable;

    if ((DWORD)(pSymbolTable - pCoffData) >= dwCoffSize) {
        return NULL;
    }

    DWORD dwSymbolSize = sizeof(COFF_SYMBOL_TABLE_ENTRY);
    PBYTE pSymbol = pSymbolTable + dwSymbolIndex * dwSymbolSize;

    if ((DWORD)(pSymbol - pCoffData) + dwSymbolSize > dwCoffSize) {
        return NULL;
    }

    PCOFF_SYMBOL_TABLE_ENTRY pEntry = (PCOFF_SYMBOL_TABLE_ENTRY)pSymbol;

    if (pEntry->Name.LongName.Zeroes == 0) {
        DWORD dwStringTableOffset = pHeader->PointerToSymbolTable + pHeader->NumberOfSymbols * dwSymbolSize;
        DWORD dwStringOffset = pEntry->Name.LongName.Offset;

        async_coff_get_string_at_offset(pCoffData, dwCoffSize, dwStringTableOffset + dwStringOffset, s_szNameBuf, sizeof(s_szNameBuf));
    }
    else {
        strncpy_s(s_szNameBuf, sizeof(s_szNameBuf), pEntry->Name.ShortName, 8);
        s_szNameBuf[8] = '\0';
    }

    return s_szNameBuf;
}

PCOFF_SYMBOL_TABLE_ENTRY async_coff_get_symbol(PBYTE pCoffData, DWORD dwCoffSize, DWORD dwSymbolIndex) {
    if (!pCoffData || dwCoffSize < sizeof(COFF_HEADER)) {
        return NULL;
    }

    PCOFF_HEADER pHeader = (PCOFF_HEADER)pCoffData;
    PBYTE pSymbolTable = pCoffData + pHeader->PointerToSymbolTable;

    if ((DWORD)(pSymbolTable - pCoffData) >= dwCoffSize) {
        return NULL;
    }

    DWORD dwSymbolSize = sizeof(COFF_SYMBOL_TABLE_ENTRY);
    PBYTE pSymbol = pSymbolTable + dwSymbolIndex * dwSymbolSize;

    if ((DWORD)(pSymbol - pCoffData) + dwSymbolSize > dwCoffSize) {
        return NULL;
    }

    return (PCOFF_SYMBOL_TABLE_ENTRY)pSymbol;
}

PVOID async_coff_resolve_symbol(PBYTE pCoffData, DWORD dwCoffSize, PCSTR pszSymbolName) {
    if (!pCoffData || dwCoffSize < sizeof(COFF_HEADER) || !pszSymbolName) {
        return NULL;
    }

    PCOFF_HEADER pHeader = (PCOFF_HEADER)pCoffData;
    DWORD dwSymbolCount = pHeader->NumberOfSymbols;
    PBYTE pSymbolTable = pCoffData + pHeader->PointerToSymbolTable;

    for (DWORD i = 0; i < dwSymbolCount; i++) {
        PCSTR pszName = async_coff_get_symbol_name(pCoffData, dwCoffSize, i);
        if (pszName && strcmp(pszName, pszSymbolName) == 0) {
            PCOFF_SYMBOL_TABLE_ENTRY pEntry = async_coff_get_symbol(pCoffData, dwCoffSize, i);
            if (pEntry && pEntry->SectionNumber > 0) {
                PCOFF_SECTION pSection = async_coff_get_section(pCoffData, dwCoffSize, pEntry->SectionNumber - 1);
                if (pSection) {
                    ULONG_PTR dwDataAddr = (ULONG_PTR)pSection->PointerToRawData + pEntry->Value;
                    if (dwDataAddr < (ULONG_PTR)dwCoffSize) {
                        return pCoffData + dwDataAddr;
                    }
                }
            }
        }

        PCOFF_SYMBOL_TABLE_ENTRY pEntry2 = async_coff_get_symbol(pCoffData, dwCoffSize, i);
        if (pEntry2) {
            i += pEntry2->NumberOfAuxSymbols;
        }
    }

    return NULL;
}

BOOL async_bof_patch_symbol(
    PBYTE pCoffData,
    DWORD dwCoffSize,
    PCSTR pszSymbolName,
    PVOID pNewFuncAddr,
    PASYNC_PATCH_RESULT pResult) {

    if (!pCoffData || !pszSymbolName || !pNewFuncAddr || !pResult) {
        if (pResult) {
            pResult->success = FALSE;
            strncpy_s(pResult->errorMsg, sizeof(pResult->errorMsg), "Invalid parameters", _TRUNCATE);
        }
        return FALSE;
    }

    PCOFF_HEADER pHeader = (PCOFF_HEADER)pCoffData;
    DWORD dwSectionCount = 0;
    PCOFF_SECTION pSections = async_coff_get_sections(pCoffData, dwCoffSize, &dwSectionCount);

    if (!pSections) {
        pResult->success = FALSE;
        strncpy_s(pResult->errorMsg, sizeof(pResult->errorMsg), "Failed to get sections", _TRUNCATE);
        return FALSE;
    }

    for (DWORD s = 0; s < dwSectionCount; s++) {
        PCOFF_SECTION pSection = &pSections[s];
        if (pSection->PointerToRelocations == 0 || pSection->NumberOfRelocations == 0) {
            continue;
        }

        for (DWORD r = 0; r < pSection->NumberOfRelocations; r++) {
            PCOFF_RELOCATION pReloc = async_coff_get_relocation(pCoffData, dwCoffSize, pSection, r);
            if (!pReloc) {
                continue;
            }

            if (pReloc->SymbolTableIndex >= pHeader->NumberOfSymbols) {
                continue;
            }

            PCSTR pszRelocName = async_coff_get_symbol_name(pCoffData, dwCoffSize, pReloc->SymbolTableIndex);
            if (!pszRelocName || strcmp(pszRelocName, pszSymbolName) != 0) {
                continue;
            }

            if (pReloc->Type == COFF_REL_TYPE_AMD64_RELATIVE) {
                PBYTE pTargetAddr = pCoffData + pSection->PointerToRawData + pReloc->VirtualAddress;

                if ((ULONG_PTR)(pTargetAddr - pCoffData) + sizeof(INT32) > dwCoffSize) {
                    continue;
                }

                INT64 distance = (INT64)((ULONG_PTR)pNewFuncAddr - (ULONG_PTR)pTargetAddr - 4);

                *(INT32*)pTargetAddr = (INT32)distance;

                pResult->numPatched++;

                return TRUE;
            }
            else if (pReloc->Type == COFF_REL_TYPE_AMD64_ADDR64) {
                PBYTE pTargetAddr = pCoffData + pSection->PointerToRawData + pReloc->VirtualAddress;

                if ((ULONG_PTR)(pTargetAddr - pCoffData) + sizeof(ULONG64) > dwCoffSize) {
                    continue;
                }

                *(ULONG64*)pTargetAddr = (ULONG64)pNewFuncAddr;

                pResult->numPatched++;

                return TRUE;
            }
        }
    }

    pResult->numFailed++;
    strncpy_s(pResult->errorMsg, sizeof(pResult->errorMsg), "Symbol not found or unsupported reloc type", _TRUNCATE);
    return FALSE;
}

BOOL async_bof_patch_imports(
    PBYTE pCoffData,
    DWORD dwCoffSize,
    PCSTR pszModuleName,
    PCSTR pszFuncName,
    PVOID pNewFuncAddr,
    PASYNC_PATCH_RESULT pResult) {

    if (!pCoffData || !pszModuleName || !pszFuncName || !pNewFuncAddr || !pResult) {
        if (pResult) {
            pResult->success = FALSE;
            strncpy_s(pResult->errorMsg, sizeof(pResult->errorMsg), "Invalid parameters", _TRUNCATE);
        }
        return FALSE;
    }

    char szFullName[256];
    snprintf(szFullName, sizeof(szFullName), "%s$%s", pszModuleName, pszFuncName);

    return async_bof_patch_symbol(pCoffData, dwCoffSize, szFullName, pNewFuncAddr, pResult);
}

static BOOL async_bof_save_original_address(
    PBYTE pCoffData,
    DWORD dwCoffSize,
    PCSTR pszImportName,
    PCSTR pszFuncName) {

    PCOFF_HEADER pHeader = (PCOFF_HEADER)pCoffData;
    DWORD dwSectionCount = pHeader->NumberOfSections;
    DWORD dwOptHeaderSize = pHeader->SizeOfOptionalHeader;
    PCOFF_SECTION pSections = (PCOFF_SECTION)(pCoffData + sizeof(COFF_HEADER) + dwOptHeaderSize);
    if ((PBYTE)(pSections + dwSectionCount) > pCoffData + dwCoffSize) {
        return FALSE;
    }

    for (DWORD s = 0; s < dwSectionCount; s++) {
        PCOFF_SECTION pSection = &pSections[s];
        if (pSection->PointerToRelocations == 0 || pSection->NumberOfRelocations == 0) {
            continue;
        }

        for (DWORD r = 0; r < pSection->NumberOfRelocations; r++) {
            PCOFF_RELOCATION pReloc = async_coff_get_relocation(pCoffData, dwCoffSize, pSection, r);
            if (!pReloc) continue;

            if (pReloc->SymbolTableIndex >= pHeader->NumberOfSymbols) continue;

            PCSTR pszRelocName = async_coff_get_symbol_name(pCoffData, dwCoffSize, pReloc->SymbolTableIndex);
            if (!pszRelocName || strcmp(pszRelocName, pszImportName) != 0) continue;

            PBYTE pTargetAddr = pCoffData + pSection->PointerToRawData + pReloc->VirtualAddress;
            ULONG_PTR originalAddr = 0;

            if ((ULONG_PTR)(pTargetAddr - pCoffData) + sizeof(ULONG64) > dwCoffSize) {
                continue;
            }

            if (pReloc->Type == COFF_REL_TYPE_AMD64_RELATIVE) {
                originalAddr = (ULONG_PTR)pTargetAddr + 4 + (INT32)(*(INT32*)pTargetAddr);
            }
            else if (pReloc->Type == COFF_REL_TYPE_AMD64_ADDR64) {
                originalAddr = *(ULONG64*)pTargetAddr;
            }
            else {
                continue;
            }

            if (!originalAddr) continue;

            char origVarName[256];
            snprintf(origVarName, sizeof(origVarName), "g_orig_%s", pszFuncName);

            PVOID pOrigVar = async_coff_resolve_symbol(pCoffData, dwCoffSize, origVarName);
            if (pOrigVar) {
                *(ULONG_PTR*)pOrigVar = originalAddr;
                return TRUE;
            }
            return FALSE;
        }
    }
    return FALSE;
}

BOOL async_bof_patch_coff(
    PBYTE pCoffData,
    DWORD dwCoffSize,
    ASYNC_PROXY_RESOLVER pfnResolveProxy,
    PASYNC_PATCH_RESULT pResult) {

    if (!pCoffData || !pResult) {
        return FALSE;
    }

    memset(pResult, 0, sizeof(ASYNC_PATCH_RESULT));

    typedef struct {
        const char* importName;
        const char* proxyName;
        const char* funcName;
    } PATCH_ENTRY;

    static const PATCH_ENTRY entries[] = {
        {"beacon$BeaconPrintf",         "proxy_BeaconPrintf",         "BeaconPrintf"},
        {"beacon$BeaconOutput",         "proxy_BeaconOutput",         "BeaconOutput"},
        {"beacon$BeaconWakeup",         "proxy_BeaconWakeup",         "BeaconWakeup"},
        {"beacon$BeaconGetStopJobEvent","proxy_BeaconGetStopJobEvent","BeaconGetStopJobEvent"},
        {"beacon$BeaconDataParse",      "proxy_BeaconDataParse",      "BeaconDataParse"},
        {"beacon$BeaconDataInt",        "proxy_BeaconDataInt",        "BeaconDataInt"},
        {"beacon$BeaconDataShort",      "proxy_BeaconDataShort",      "BeaconDataShort"},
        {"beacon$BeaconDataLength",     "proxy_BeaconDataLength",     "BeaconDataLength"},
        {"beacon$BeaconDataExtract",    "proxy_BeaconDataExtract",    "BeaconDataExtract"},
    };

    for (int i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        PVOID pProxyAddr = pfnResolveProxy
            ? pfnResolveProxy(entries[i].proxyName)
            : async_coff_resolve_symbol(pCoffData, dwCoffSize, entries[i].proxyName);
        if (!pProxyAddr) {
            pResult->numFailed++;
            continue;
        }

        async_bof_save_original_address(pCoffData, dwCoffSize,
            entries[i].importName, entries[i].funcName);

        ASYNC_PATCH_RESULT tmp = { 0 };
        async_bof_patch_imports(pCoffData, dwCoffSize, "beacon",
            entries[i].importName + 7, pProxyAddr, &tmp);
        pResult->numPatched += tmp.numPatched;
        pResult->numFailed += tmp.numFailed;
    }

    if (pResult->numFailed == 0) {
        pResult->success = TRUE;
    }
    else {
        snprintf(pResult->errorMsg, sizeof(pResult->errorMsg),
            "Failed to patch %lu import(s); ensure proxy functions are resolvable",
            pResult->numFailed);
    }

    return pResult->success;
}
