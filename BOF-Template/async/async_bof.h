#ifndef _ASYNC_BOF_H_
#define _ASYNC_BOF_H_

#include <windows.h>

extern void async_init(char* args, int len);
extern HANDLE async_get_stop_event(void);
extern BOOL async_should_stop(DWORD dwMs);
extern void async_wakeup(void);
extern void async_stopping(void);
extern void async_stopped(void);
extern void async_printf(int type, const char* fmt, ...);
extern void async_vprintf(int type, const char* fmt, va_list args);

extern int async_get_status(void);
extern BOOL async_is_initialized(void);
extern void async_cleanup(void);

#define ASYNC_ALERT(fmt, ...) do { async_printf(CALLBACK_OUTPUT, fmt, ##__VA_ARGS__); async_wakeup(); } while(0)
#define ASYNC_CHECK_STOP()    async_should_stop(0)

// Outflank blog-aligned API wrappers
static inline void BeaconWakeup(void) { async_wakeup(); }
static inline HANDLE BeaconGetStopJobEvent(void) { return async_get_stop_event(); }

#endif
