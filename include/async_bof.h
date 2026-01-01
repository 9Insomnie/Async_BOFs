/**
 * @file async_bof.h
 * @brief Async BOF Development Header for BOF Authors
 * @author Offensive Security Researcher
 * @date 2025
 *
 * This header is for BOF developers who want to write async-safe BOFs.
 * Include this in your BOF source code to access async APIs.
 *
 * USAGE:
 *   1. Include this header in your BOF: #include "async_bof.h"
 *   2. Implement the standard bof_main() entry point
 *   3. Call BeaconGetStopJobEvent() to get stop signal
 *   4. Call BeaconWakeup() to wake beacon on important events
 *   5. Always exit gracefully when stop event is signaled
 */

#ifndef ASYNC_BOF_H
#define ASYNC_BOF_H

#include <windows.h>

// ============================================================================
// BEACON API DECLARATIONS (Standard BOF Format)
// ============================================================================

// Standard Beacon output functions
DECLSPEC_IMPORT void    BeaconPrintf(int type, const char* fmt, ...);
DECLSPEC_IMPORT void    BeaconOutput(int type, const void* data, int len);

// Memory management
DECLSPEC_IMPORT void*   BeaconAlloc(size_t size);
DECLSPEC_IMPORT void    BeaconFree(void* ptr);

// Async-specific APIs
DECLSPEC_IMPORT BOOL    BeaconWakeup(void);
DECLSPEC_IMPORT HANDLE  BeaconGetStopJobEvent(void);

// Data parsing functions
DECLSPEC_IMPORT void*   BeaconGetValue(datap* parser, int type);
DECLSPEC_IMPORT void*   BeaconGetParsedData(datap* parser);

// ============================================================================
// ASYNC BOF MACROS AND HELPERS
// ============================================================================

/**
 * @brief Check if we should stop (helper macro)
 *
 * Usage in BOF monitoring loop:
 *   if (ASYNC_SHOULD_STOP()) {
 *       Cleanup();
 *       return;
 *   }
 */
#define ASYNC_SHOULD_STOP() \
    (WaitForSingleObject(BeaconGetStopJobEvent(), 0) == WAIT_OBJECT_0)

/**
 * @brief Check stop with timeout (helper macro)
 *
 * Usage:
 *   ASYNC_WAIT_OR_STOP(5000) {  // Wait 5 seconds or until stop
 *       // Do work
 *   }
 */
#define ASYNC_WAIT_OR_STOP(timeout) \
    for (DWORD __dwResult = WaitForSingleObject(BeaconGetStopJobEvent(), (timeout)); \
         __dwResult != WAIT_OBJECT_0; \
         __dwResult = WAIT_OBJECT_0)

/**
 * @brief Alert and wake beacon (helper macro)
 *
 * Use this when you detect something important that needs immediate attention.
 *
 * Usage:
 *   if (IsAdminLogon()) {
 *       ASYNC_ALERT("[ALERT] Admin logon detected!");
 *   }
 */
#define ASYNC_ALERT(fmt, ...) \
    do { \
        BeaconPrintf(0, fmt, ##__VA_ARGS__); \
        BeaconWakeup(); \
    } while(0)

/**
 * @brief Async-aware monitoring loop helper
 *
 * This macro provides a standard pattern for long-running BOFs.
 *
 * Usage:
 *   ASYNC_MONITOR_LOOP(1000) {  // Check every 1 second
 *       // Your monitoring code here
 *       CheckForEvents();
 *   }
 */
#define ASYNC_MONITOR_LOOP(interval_ms) \
    for (BOOL __bRunning = TRUE; __bRunning; __bRunning = FALSE) \
        while (WaitForSingleObject(BeaconGetStopJobEvent(), (interval_ms)) != WAIT_OBJECT_0)

// ============================================================================
// EXAMPLE BOF TEMPLATES
// ============================================================================

/**
 * @brief Template for a simple async monitoring BOF
 *
 * PASTE THIS INTO YOUR BOF AND CUSTOMIZE:
 */
/*
#include "async_bof.h"

void bof_main(datap* parser, int argc)
{
    BeaconPrintf(0, "[Async BOF] Starting...\n");

    // Get stop event handle
    HANDLE hStop = BeaconGetStopJobEvent();
    if (hStop == NULL) {
        BeaconPrintf(0, "[Async BOF] ERROR: Failed to get stop event\n");
        return;
    }

    // Initialize your resources here
    // Example: EVT_HANDLE hSub = EvtSubscribe(...);

    // Main monitoring loop
    while (TRUE) {
        // Check stop signal every second
        DWORD dwResult = WaitForSingleObject(hStop, 1000);

        if (dwResult == WAIT_OBJECT_0) {
            // Stop requested!
            BeaconPrintf(0, "[Async BOF] Shutting down...\n");
            break;
        }

        // YOUR MONITORING CODE HERE
        // Example: Check for logon events

        // If you detect something important:
        if (0) {  // Replace with your condition
            // Alert and wake beacon immediately
            ASYNC_ALERT("[ALERT] Something important happened!");
        }
    }

    // Cleanup resources
    // Example: EvtClose(hSub);

    BeaconPrintf(0, "[Async BOF] Exited cleanly\n");
}
*/

// ============================================================================
// TROUBLESHOOTING MACROS
// ============================================================================

#ifdef DEBUG_ASYNC_BOF
    #define ASYNC_DEBUG(fmt, ...) BeaconPrintf(0, "[DEBUG] " fmt, ##__VA_ARGS__)
#else
    #define ASYNC_DEBUG(fmt, ...) // Nothing
#endif

// ============================================================================
// THREAD-SAFE MEMORY ALLOCATION HELPERS
// ============================================================================

/**
 * @brief Thread-safe string duplication
 *
 * Use this instead of strdup() for Beacon-allocated memory.
 */
static inline char* AsyncStrDup(const char* src)
{
    if (src == NULL) return NULL;

    size_t len = strlen(src);
    char* dst = (char*)BeaconAlloc(len + 1);
    if (dst != NULL) {
        memcpy(dst, src, len);
        dst[len] = '\0';
    }
    return dst;
}

/**
 * @brief Thread-safe wide string duplication
 */
static inline wchar_t* AsyncStrDupW(const wchar_t* src)
{
    if (src == NULL) return NULL;

    size_t len = wcslen(src);
    wchar_t* dst = (wchar_t*)BeaconAlloc((len + 1) * sizeof(wchar_t));
    if (dst != NULL) {
        memcpy(dst, src, len * sizeof(wchar_t));
        dst[len] = L'\0';
    }
    return dst;
}

// ============================================================================
// BEST PRACTICES FOR ASYNC BOFS
// ============================================================================

/**
 * DO'S:
 * ✓ Check stop event frequently (every 1-5 seconds)
 * ✓ Cleanup resources before exiting
 * ✓ Use BeaconWakeup() for critical events
 * ✓ Keep memory usage low
 * ✓ Use error handling
 * ✓ Log startup and shutdown
 *
 * DON'TS:
 * ✗ Never use infinite loops without stop checks
 * ✗ Never leak resources (events, handles, memory)
 * ✗ Never call blocking functions with long timeouts
 * ✗ Never assume Beacon APIs work during Sleepmask
 * ✗ Never use TerminateThread or other forceful stops
 */

#endif // ASYNC_BOF_H
