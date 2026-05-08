#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

#include "mock_async.h"
#include "mock.h"
#include "../async/async_protocol.h"
#include <string>

namespace bof {
    namespace async_mock {
        static HANDLE g_hManualStopEvent = NULL;
        static BOOL g_bWakeupCalled = FALSE;
        static std::string g_sLastMessage;
        static std::vector<std::string> g_aMessages;

        void setMockStopEvent(HANDLE hEvent) {
        }

        HANDLE getMockStopEvent(void) {
            return g_hManualStopEvent;
        }

        std::string getLastAsyncMessage(void) {
            if (!g_aMessages.empty()) {
                return g_aMessages.back();
            }
            return "";
        }

        const std::vector<std::string>& getAllMessages(void) {
            return g_aMessages;
        }

        BOOL wasWakeupCalled(void) {
            return g_bWakeupCalled;
        }

        void triggerStopEvent(void) {
            HANDLE hEvent = getMockStopEvent();
            if (hEvent) {
                SetEvent(hEvent);
            }
        }

        void reset(void) {
            if (g_hManualStopEvent) {
                CloseHandle(g_hManualStopEvent);
            }
            g_hManualStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
            g_bWakeupCalled = FALSE;
            g_sLastMessage.clear();
            g_aMessages.clear();
        }

        void recordMessage(const char* msg, int len) {
            g_sLastMessage = std::string(msg, len);
            g_aMessages.push_back(std::string(msg, len));
            if (len > 13 && memcmp(msg, "\x00ASYNCPROTO\x00", 13) == 0) {
                const char* p = msg + 13;
                if (strncmp(p, "WAKEUP", 6) == 0) {
                    g_bWakeupCalled = TRUE;
                }
            }
        }

        void recordOutput(int type, const char* data, int len) {
            bof::output::addEntry(type, data, len);
        }
    }
}

namespace bof {
    template <typename... T>
    std::vector<bof::output::OutputEntry> runMockedAsync(
        void (*entry)(char*, int), T&&...v) {
        BEACON_INFO beaconInfo = bof::mock::setupMockBeacon(bof::profile::defaultStage);
        bof::mock::setBeaconInfo(beaconInfo);
        bof::output::reset();
        bof::async_mock::reset();

        bof::mock::BofData args;
        args.pack(std::forward<T>(v)...);
        entry(args.get(), args.size());
        return bof::output::getOutputs();
    }

    template <>
    std::vector<bof::output::OutputEntry> runMockedAsync<HANDLE>(
        void (*entry)(char*, int), HANDLE hStopEvent) {
        BEACON_INFO beaconInfo = bof::mock::setupMockBeacon(bof::profile::defaultStage);
        bof::mock::setBeaconInfo(beaconInfo);
        bof::output::reset();
        bof::async_mock::reset();

        bof::async_mock::setMockStopEvent(hStopEvent);
        char stop_arg[64];
        int len = snprintf(stop_arg, sizeof(stop_arg), "\x1ASTOP\x1A%08X", (DWORD)(ULONG_PTR)hStopEvent);
        entry(stop_arg, len);
        return bof::output::getOutputs();
    }
}
