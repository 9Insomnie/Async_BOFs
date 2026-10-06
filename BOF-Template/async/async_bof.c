#include "async_bof.h"
#include "async_protocol.h"
#include <stdio.h>

#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include "..\beacon.h"
#ifdef __cplusplus
}
#endif

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

    ULONG_PTR handle_val = async_parse_handle_from_args(args, len);
    if (handle_val == 0) {
        g_Status = ASYNC_STATUS_NO_STOP_EVENT;
        return;
    }

    HANDLE hEvent = (HANDLE)handle_val;
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

    char msg_buf[4096];
    int text_len = vsnprintf(msg_buf, sizeof(msg_buf) - 1, fmt, args);
    if (text_len <= 0) {
        return;
    }
    if (text_len >= (int)sizeof(msg_buf)) {
        text_len = (int)sizeof(msg_buf) - 1;
    }
    msg_buf[text_len] = '\0';

    BeaconOutput(type, msg_buf, text_len);
}

void async_printf(int type, const char* fmt, ...) {
    if (!g_bInitialized) {
        return;
    }

    char msg_buf[4096];
    va_list args;
    va_start(args, fmt);
    int text_len = vsnprintf(msg_buf, sizeof(msg_buf) - 1, fmt, args);
    va_end(args);
    if (text_len <= 0) {
        return;
    }
    if (text_len >= (int)sizeof(msg_buf)) {
        text_len = (int)sizeof(msg_buf) - 1;
    }
    msg_buf[text_len] = '\0';

    BeaconOutput(type, msg_buf, text_len);
}

void async_notify_vprintf(int type, const char* fmt, va_list args) {
    if (!g_bInitialized) {
        return;
    }

    char msg_buf[4096];
    int text_len = vsnprintf(msg_buf, sizeof(msg_buf) - 1, fmt, args);
    if (text_len <= 0) {
        return;
    }
    if (text_len >= (int)sizeof(msg_buf)) {
        text_len = (int)sizeof(msg_buf) - 1;
    }
    msg_buf[text_len] = '\0';

    char proto[8192];
    int msg_len = async_build_msg(proto, sizeof(proto), ASYNC_CMD_DATA, msg_buf, text_len);
    if (msg_len > 0) {
        BeaconOutput(CALLBACK_OUTPUT, proto, msg_len);
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
        BeaconOutput(CALLBACK_OUTPUT, msg_buf, msg_len);
    }
}

void async_stopping(void) {
    if (!g_bInitialized) {
        return;
    }

    char msg_buf[256];
    int msg_len = async_build_msg(msg_buf, sizeof(msg_buf), ASYNC_CMD_STOPPING, NULL, 0);
    if (msg_len > 0) {
        BeaconOutput(CALLBACK_OUTPUT, msg_buf, msg_len);
    }
}

void async_stopped(void) {
    if (!g_bInitialized) {
        return;
    }

    char msg_buf[256];
    int msg_len = async_build_msg(msg_buf, sizeof(msg_buf), ASYNC_CMD_STOPPED, NULL, 0);
    if (msg_len > 0) {
        BeaconOutput(CALLBACK_OUTPUT, msg_buf, msg_len);
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
