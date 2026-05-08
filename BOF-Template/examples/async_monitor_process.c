#include <Windows.h>
#include <winuser.h>
#include "..\async\async_bof.h"

#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "..\beacon.h"
}

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfTotalThreads;
    ULONG AccessKey;
    LONGLONG UniqueProcessId;
    ULONGLONG CommitSize;
    LONGLONG TotalCycleTime;
    ULONGLONG UserCycleTime;
    ULONGLONG Signature;
    LARGE_INTEGER CreateTime;
    ULONGLONG QuotaPeakPagedPoolUsage;
    ULONGLONG QuotaPagedPoolUsage;
    ULONGLONG QuotaPeakNonPagedPoolUsage;
    ULONGLONG QuotaNonPagedPoolUsage;
    LONGLONG PagefileUsage;
    LONGLONG PeakPagefileUsage;
    LONGLONG PrivatePageCount;
    LARGE_INTEGER ModifiedPageCount;
    ULONG ExecuteOptions;
    UCHAR UniqueProcessDisableFState;
    ULONG GdiCellps;
    UCHAR Flags;
    UCHAR NumbCells;
    UCHAR CorePrmSystemDll;
    ULONG DeleteFlags;
    wchar_t ImageName[260];
    LONG BasePriority;
    HANDLE UniqueProcessIdUnused;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONGLONG_PTR ptrVMC;
    ULONGLONG_PTR ptrCommitCharge;
    ULONGLONG_PTR PeakMemory;
    ULONGLONG_ptr PsMAfreeSystemMemory;
    ULONGLONG_ptr pszPrototypeOsVersion;
    ULONG_PTR ThreadArrayHACK;
    ULONG OverflowCounter;
    ULONG_PTR ThreadList[1];
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef NTSTATUS(NTAPI* FN_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

static FN_NtQuerySystemInformation g_pNtQuerySystemInformation = NULL;

static BOOL initNtQuerySystemInformation(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        hNtdll = LoadLibraryA("ntdll.dll");
        if (!hNtdll) {
            return FALSE;
        }
    }
    g_pNtQuerySystemInformation = (FN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    return (g_pNtQuerySystemInformation != NULL);
}

static BOOL isProcessRunning(PCWSTR wszProcessName, PULONGLONG pOutPid) {
    if (!g_pNtQuerySystemInformation) {
        return FALSE;
    }

    ULONG ulSize = 0;
    NTSTATUS status = g_pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ulSize);
    if (status != 0xC0000023 && status != 0) {
        return FALSE;
    }

    PBYTE pBuffer = (PBYTE)malloc(ulSize);
    if (!pBuffer) {
        return FALSE;
    }

    status = g_pNtQuerySystemInformation(SystemProcessInformation, pBuffer, ulSize, &ulSize);
    if (!NT_SUCCESS(status)) {
        free(pBuffer);
        return FALSE;
    }

    PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)pBuffer;
    BOOL bFound = FALSE;

    while (pInfo) {
        if (pInfo->ImageName.Buffer && wcslen(pInfo->ImageName.Buffer) > 0) {
            if (_wcsicmp(pInfo->ImageName.Buffer, wszProcessName) == 0) {
                if (pOutPid) {
                    *pOutPid = (ULONGLONG)pInfo->UniqueProcessId;
                }
                bFound = TRUE;
                break;
            }
        }

        if (pInfo->NextEntryOffset == 0) {
            break;
        }
        pInfo = (PSYSTEM_PROCESS_INFO)((BYTE*)pInfo + pInfo->NextEntryOffset);
    }

    free(pBuffer);
    return bFound;
}

static void enumerateProcesses(BOOL bAlertsOnly) {
    if (!g_pNtQuerySystemInformation) {
        return;
    }

    ULONG ulSize = 0;
    NTSTATUS status = g_pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ulSize);
    if (status != 0xC0000023 && status != 0) {
        return;
    }

    PBYTE pBuffer = (PBYTE)malloc(ulSize);
    if (!pBuffer) {
        return;
    }

    status = g_pNtQuerySystemInformation(SystemProcessInformation, pBuffer, ulSize, &ulSize);
    if (!NT_SUCCESS(status)) {
        free(pBuffer);
        return;
    }

    PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)pBuffer;
    int count = 0;

    while (pInfo) {
        if (pInfo->ImageName.Buffer && wcslen(pInfo->ImageName.Buffer) > 0) {
            if (!bAlertsOnly) {
                BeaconPrintf(CALLBACK_OUTPUT, "    [PID: %llu] %ls", 
                    (ULONGLONG)pInfo->UniqueProcessId, 
                    pInfo->ImageName.Buffer);
            }
            count++;
        }

        if (pInfo->NextEntryOffset == 0) {
            break;
        }
        pInfo = (PSYSTEM_PROCESS_INFO)((BYTE*)pInfo + pInfo->NextEntryOffset);
    }

    free(pBuffer);
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    wchar_t targetProcess[256] = { 0 };
    DWORD dwCheckIntervalMs = 2000;
    BOOL bListProcesses = FALSE;
    BOOL bMonitorOnce = FALSE;

    int initialLength = parser.length;
    if (initialLength > 0) {
        int procNameLen = 0;
        char* procNameBuf = BeaconDataPtr(&parser, &procNameLen);
        if (procNameBuf && procNameLen > 0) {
            wchar_t* wbuf = (wchar_t*)malloc(procNameLen * 2 + 2);
            if (wbuf) {
                MultiByteToWideChar(CP_ACP, 0, procNameBuf, procNameLen, wbuf, procNameLen * 2);
                wbuf[procNameLen] = L'\0';
                wcsncpy_s(targetProcess, 256, wbuf, 255);
                free(wbuf);
            }
        }
    }

    if (parser.length > 0) {
        dwCheckIntervalMs = (DWORD)BeaconDataInt(&parser);
    }
    if (parser.length > 0) {
        int listFlag = BeaconDataInt(&parser);
        bListProcesses = (listFlag != 0);
    }
    if (parser.length > 0) {
        int monitorOnceFlag = BeaconDataInt(&parser);
        bMonitorOnce = (monitorOnceFlag != 0);
    }

    async_init(args, len);

    if (!async_is_initialized()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Async BOF not properly initialized. This BOF requires the async_bof.cna loader.");
        return;
    }

    HANDLE hStop = async_get_stop_event();
    if (!hStop) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No stop event available");
        return;
    }

    if (!initNtQuerySystemInformation()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to initialize NtQuerySystemInformation");
        return;
    }

    if (bListProcesses) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Current processes:");
        enumerateProcesses(FALSE);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Done listing processes");
        return;
    }

    if (wcslen(targetProcess) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No target process specified");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Usage: async_monitor_process <process_name> [interval_ms] [list_flag] [once_flag]");
        BeaconPrintf(CALLBACK_OUTPUT, "[*]   process_name: Process name to monitor (e.g., 'notepad.exe')");
        BeaconPrintf(CALLBACK_OUTPUT, "[*]   interval_ms: Check interval in milliseconds (default: 2000)");
        BeaconPrintf(CALLBACK_OUTPUT, "[*]   list_flag: 1 to list processes instead of monitoring (default: 0)");
        BeaconPrintf(CALLBACK_OUTPUT, "[*]   once_flag: 1 to exit after first detection (default: 0)");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Async Process Monitor started");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Monitoring for: %ls", targetProcess);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Check interval: %lu ms", dwCheckIntervalMs);
    if (bMonitorOnce) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Mode: Exit after first detection");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Waiting... (Use 'async_stop' to stop)");

    ULONGLONG ullPreviousPid = 0;
    DWORD dwPollCount = 0;

    while (!async_should_stop(dwCheckIntervalMs)) {
        ULONGLONG ullCurrentPid = 0;
        BOOL bFound = isProcessRunning(targetProcess, &ullCurrentPid);

        dwPollCount++;

        if (bFound) {
            if (ullCurrentPid != ullPreviousPid) {
                BeaconPrintf(CALLBACK_OUTPUT, "");
                BeaconPrintf(CALLBACK_OUTPUT, "[!] PROCESS START DETECTED!");
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Process: %ls", targetProcess);
                BeaconPrintf(CALLBACK_OUTPUT, "[!] PID: %llu", ullCurrentPid);
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Poll count: %lu", dwPollCount);

                ASYNC_ALERT("[!] PROCESS START: %ls (PID: %llu)", targetProcess, ullCurrentPid);

                ullPreviousPid = ullCurrentPid;

                if (bMonitorOnce) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] Exiting after detection (once mode)");
                    break;
                }
            }
        }
        else {
            if (ullPreviousPid != 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[i] Process %ls exited (was PID: %llu)", targetProcess, ullPreviousPid);
                ullPreviousPid = 0;
            }
        }
    }

    async_stopping();
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Async Process Monitor stopped (polled %lu times)", dwPollCount);
    async_stopped();
}
