#ifndef _MOCK_ASYNC_H_
#define _MOCK_ASYNC_H_

#include <windows.h>
#include <string>
#include <vector>
#include "../async/async_protocol.h"

namespace bof {
    namespace async_mock {
        void setMockStopEvent(HANDLE hEvent);
        HANDLE getMockStopEvent(void);
        std::string getLastAsyncMessage(void);
        BOOL wasWakeupCalled(void);
        void triggerStopEvent(void);
        void reset(void);
    }

    template <typename... T>
    std::vector<bof::output::OutputEntry> runMockedAsync(
        void (*entry)(char*, int), T&&...v);
}

extern "C" {
    void async_init(char* args, int len);
    HANDLE async_get_stop_event(void);
    BOOL async_should_stop(DWORD dwMs);
    void async_wakeup(void);
    void async_stopping(void);
    void async_stopped(void);
    void async_printf(int type, const char* fmt, ...);
    int async_get_status(void);
    BOOL async_is_initialized(void);
    void async_cleanup(void);
}

#endif
