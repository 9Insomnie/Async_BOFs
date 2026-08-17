#ifndef _ASYNC_BOF_PATCH_H_
#define _ASYNC_BOF_PATCH_H_

#include <windows.h>

typedef struct _COFF_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    DWORD SizeOfOptionalHeader;
    WORD Characteristics;
} COFF_HEADER, *PCOFF_HEADER;

typedef struct _COFF_SECTION {
    char Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLineNumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLineNumbers;
    DWORD Characteristics;
} COFF_SECTION, *PCOFF_SECTION;

typedef struct _COFF_RELOCATION {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD Type;
} COFF_RELOCATION, *PCOFF_RELOCATION;

#define COFF_REL_TYPE_I386_ABSOLUTE 0x0006
#define COFF_REL_TYPE_AMD64_RELATIVE 0x0004
#define COFF_REL_TYPE_AMD64_ADDR32NB 0x0003
#define COFF_REL_TYPE_AMD64_ADDR64 0x0001

typedef struct _COFF_SYMBOL_TABLE_ENTRY {
    union {
        char ShortName[8];
        struct {
            DWORD Zeroes;
            DWORD Offset;
        } LongName;
    } Name;
    DWORD Value;
    WORD SectionNumber;
    WORD Type;
    BYTE StorageClass;
    BYTE NumberOfAuxSymbols;
} COFF_SYMBOL_TABLE_ENTRY, *PCOFF_SYMBOL_TABLE_ENTRY;

typedef struct _COFF_STRING_TABLE {
    DWORD TotalSize;
    char* Strings;
} COFF_STRING_TABLE, *PCOFF_STRING_TABLE;

typedef struct _ASYNC_PATCH_RESULT {
    BOOL success;
    DWORD numPatched;
    DWORD numFailed;
    char errorMsg[256];
} ASYNC_PATCH_RESULT, *PASYNC_PATCH_RESULT;

DWORD async_coff_get_section_count(PBYTE pCoffData, DWORD dwCoffSize);

PCOFF_SECTION async_coff_get_section(PBYTE pCoffData, DWORD dwCoffSize, DWORD dwSectionIndex);

PCOFF_SECTION async_coff_find_section(PBYTE pCoffData, DWORD dwCoffSize, PCSTR pszSectionName);

DWORD async_coff_get_relocation_count(PCOFF_SECTION pSection);

PCOFF_RELOCATION async_coff_get_relocation(PBYTE pCoffData, DWORD dwCoffSize, PCOFF_SECTION pSection, DWORD dwRelocIndex);

PCOFF_SECTION async_coff_get_sections(PBYTE pCoffData, DWORD dwCoffSize, PDWORD pdwSectionCount);

PCOFF_SYMBOL_TABLE_ENTRY async_coff_get_symbol(PBYTE pCoffData, DWORD dwCoffSize, DWORD dwSymbolIndex);

PCSTR async_coff_get_symbol_name(PBYTE pCoffData, DWORD dwCoffSize, DWORD dwSymbolIndex);

PVOID async_coff_resolve_symbol(PBYTE pCoffData, DWORD dwCoffSize, PCSTR pszSymbolName);

typedef PVOID (*ASYNC_PROXY_RESOLVER)(PCSTR pszProxyName);

BOOL async_bof_patch_imports(
    PBYTE pCoffData,
    DWORD dwCoffSize,
    PCSTR pszModuleName,
    PCSTR pszFuncName,
    PVOID pNewFuncAddr,
    PASYNC_PATCH_RESULT pResult);

BOOL async_bof_patch_symbol(
    PBYTE pCoffData,
    DWORD dwCoffSize,
    PCSTR pszSymbolName,
    PVOID pNewFuncAddr,
    PASYNC_PATCH_RESULT pResult);

BOOL async_bof_patch_coff(
    PBYTE pCoffData,
    DWORD dwCoffSize,
    ASYNC_PROXY_RESOLVER pfnResolveProxy,
    PASYNC_PATCH_RESULT pResult);

#endif
