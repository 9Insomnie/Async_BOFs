#include "async_bof.h"
#include "async_protocol.h"

extern "C" {
#include "..\beacon.h"
}

void* g_orig_BeaconPrintf = NULL;
void* g_orig_BeaconOutput = NULL;
void* g_orig_BeaconDataParse = NULL;
void* g_orig_BeaconDataInt = NULL;
void* g_orig_BeaconDataShort = NULL;
void* g_orig_BeaconDataLength = NULL;
void* g_orig_BeaconDataExtract = NULL;

extern "C" void async_bof_save_original(const char* name, void* addr) {
    if (strcmp(name, "BeaconPrintf") == 0) g_orig_BeaconPrintf = addr;
    else if (strcmp(name, "BeaconOutput") == 0) g_orig_BeaconOutput = addr;
    else if (strcmp(name, "BeaconDataParse") == 0) g_orig_BeaconDataParse = addr;
    else if (strcmp(name, "BeaconDataInt") == 0) g_orig_BeaconDataInt = addr;
    else if (strcmp(name, "BeaconDataShort") == 0) g_orig_BeaconDataShort = addr;
    else if (strcmp(name, "BeaconDataLength") == 0) g_orig_BeaconDataLength = addr;
    else if (strcmp(name, "BeaconDataExtract") == 0) g_orig_BeaconDataExtract = addr;
}

typedef void (*bprintf_t)(int, const char*, ...);
typedef void (*boutput_t)(int, const char*, int);
typedef void (*bdparse_t)(datap*, char*, int);
typedef int  (*bdint_t)(datap*);
typedef short (*bdshort_t)(datap*);
typedef int  (*bdlength_t)(datap*);
typedef char*(*bdextract_t)(datap*, int*);

extern "C" void proxy_BeaconPrintf(int type, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[4096];
    int len = vsnprintf(buf, sizeof(buf) - 1, fmt, args);
    va_end(args);
    if (len <= 0) return;
    buf[len] = '\0';

    char proto[8192];
    int msg_len = async_build_msg(proto, sizeof(proto), ASYNC_CMD_DATA, buf, len);
    if (msg_len > 0) {
        bprintf_t orig = (bprintf_t)g_orig_BeaconPrintf;
        if (orig)
            orig(CALLBACK_OUTPUT, "%s", proto);
    }
}

extern "C" void proxy_BeaconOutput(int type, const char* data, int len) {
    char proto[8192];
    int msg_len = async_build_msg(proto, sizeof(proto), ASYNC_CMD_DATA, data, len);
    if (msg_len > 0) {
        boutput_t orig = (boutput_t)g_orig_BeaconOutput;
        if (orig)
            orig(type, proto, msg_len);
    }
}

extern "C" void proxy_BeaconWakeup(void) {
    async_wakeup();
}

extern "C" HANDLE proxy_BeaconGetStopJobEvent(void) {
    return async_get_stop_event();
}

extern "C" void proxy_BeaconDataParse(datap* parser, char* buffer, int size) {
    bdparse_t orig = (bdparse_t)g_orig_BeaconDataParse;
    if (orig) orig(parser, buffer, size);
}

extern "C" int proxy_BeaconDataInt(datap* parser) {
    bdint_t orig = (bdint_t)g_orig_BeaconDataInt;
    return orig ? orig(parser) : 0;
}

extern "C" short proxy_BeaconDataShort(datap* parser) {
    bdshort_t orig = (bdshort_t)g_orig_BeaconDataShort;
    return orig ? orig(parser) : 0;
}

extern "C" int proxy_BeaconDataLength(datap* parser) {
    bdlength_t orig = (bdlength_t)g_orig_BeaconDataLength;
    return orig ? orig(parser) : 0;
}

extern "C" char* proxy_BeaconDataExtract(datap* parser, int* size) {
    bdextract_t orig = (bdextract_t)g_orig_BeaconDataExtract;
    return orig ? orig(parser, size) : NULL;
}
