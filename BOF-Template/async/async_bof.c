#include "async_bof.h"
#include "async_protocol.h"

#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "..\beacon.h"
}

static volatile HANDLE g_hStopEvent = NULL;
static volatile BOOL g_bInitialized = FALSE;
static volatile int g_Status = ASYNC_STATUS_NOT_INITIALIZED;

void async_init(char* args, int len) {
    if (g_bInitialized) {
        return;
    }

    if (!args || len <= 0) {
        g_Status = ASYNC_STATUS_INVALID_ARGS;
        return;
    }

    int handle_val = async_parse_handle_from_args(args, len);
    if (handle_val == 0) {
        g_Status = ASYNC_STATUS_NO_STOP_EVENT;
        return;
    }

    HANDLE hEvent = (HANDLE)(ULONG_PTR)handle_val;
    if (hEvent == NULL || hEvent == INVALID_HANDLE_VALUE) {
        g_Status = ASYNC_STATUS_NO_STOP_EVENT;
        return;
    }

    g_hStopEvent = hEvent;
    g_bInitialized = TRUE;
    g_Status = ASYNC_STATUS_OK;
}

HANDLE async_get_stop_event(void) {
    return (HANDLE)g_hStopEvent;
}

BOOL async_should_stop(DWORD dwMs) {
    if (!g_bInitialized || g_hStopEvent == NULL) {
        return TRUE;
    }

    DWORD wait_result = WaitForSingleObject((HANDLE)g_hStopEvent, dwMs);
    return (wait_result == WAIT_OBJECT_0);
}

void async_vprintf(int type, const char* fmt, va_list args) {
    if (!g_bInitialized) {
        return;
    }

    BeaconPrintf(type, fmt, args);
}

void async_printf(int type, const char* fmt, ...) {
    if (!g_bInitialized) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    BeaconPrintf(type, fmt, args);
    va_end(args);
}

void async_notify_vprintf(int type, const char* fmt, va_list args) {
    if (!g_bInitialized) {
        return;
    }

    char msg_buf[4096];
    int len = vsnprintf(msg_buf, sizeof(msg_buf) - 1, fmt, args);
    if (len <= 0) {
        return;
    }
    msg_buf[len] = '\0';

    int msg_len = async_build_msg(msg_buf, sizeof(msg_buf), ASYNC_CMD_DATA, msg_buf, len);
    if (msg_len > 0) {
        BeaconPrintf(type, "%s", msg_buf);
    }
}

void async_notify_printf(int type, const char* fmt, ...) {
    if (!g_bInitialized) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    async_notify_vprintf(type, fmt, args);
    va_end(args);
}

void async_wakeup(void) {
    if (!g_bInitialized) {
        return;
    }

    char msg_buf[256];
    int msg_len = async_build_msg(msg_buf, sizeof(msg_buf), ASYNC_CMD_WAKEUP, NULL, 0);
    if (msg_len > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", msg_buf);
    }
}

void async_stopping(void) {
    if (!g_bInitialized) {
        return;
    }

    char msg_buf[256];
    int msg_len = async_build_msg(msg_buf, sizeof(msg_buf), ASYNC_CMD_STOPPING, NULL, 0);
    if (msg_len > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", msg_buf);
    }
}

void async_stopped(void) {
    if (!g_bInitialized) {
        return;
    }

    char msg_buf[256];
    int msg_len = async_build_msg(msg_buf, sizeof(msg_buf), ASYNC_CMD_STOPPED, NULL, 0);
    if (msg_len > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s", msg_buf);
    }
}

int async_get_status(void) {
    return g_Status;
}

BOOL async_is_initialized(void) {
    return g_bInitialized;
}

void async_cleanup(void) {
    g_bInitialized = FALSE;
    g_hStopEvent = NULL;
    g_Status = ASYNC_STATUS_NOT_INITIALIZED;
}
