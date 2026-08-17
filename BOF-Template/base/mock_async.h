#ifndef _MOCK_ASYNC_H_
#define _MOCK_ASYNC_H_

#include <windows.h>
#include <string>
#include <vector>
#include "mock.h"
#include "../async/async_protocol.h"

namespace bof {
    namespace async_mock {
        void setMockStopEvent(HANDLE hEvent);
        HANDLE getMockStopEvent(void);
        std::string getLastAsyncMessage(void);
        const std::vector<std::string>& getAllMessages(void);
        BOOL wasWakeupCalled(void);
        void triggerStopEvent(void);
        void reset(void);
        void recordMessage(const char* msg, int len);
        void recordOutput(int type, const char* data, int len);
    }

    template <typename... T>
    std::vector<bof::output::OutputEntry> runMockedAsync(
        void (*entry)(char*, int), T&&...v);

    template <>
    std::vector<bof::output::OutputEntry> runMockedAsync<HANDLE>(
        void (*entry)(char*, int), HANDLE&& hStopEvent);
}

extern "C" {
    void async_init(char* args, int len);
    HANDLE async_get_stop_event(void);
    BOOL async_should_stop(DWORD dwMs);
    void async_wakeup(void);
    void async_stopping(void);
    void async_stopped(void);
    void async_printf(int type, const char* fmt, ...);
    void async_vprintf(int type, const char* fmt, va_list args);
    int async_get_status(void);
    BOOL async_is_initialized(void);
    void async_cleanup(void);
}

#endif
