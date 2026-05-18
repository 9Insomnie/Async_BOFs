#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "..\async\async_bof.h"

#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "..\beacon.h"
}

#pragma comment(lib, "ws2_32")

static BOOL try_connect(const char* host, int port, int timeout_ms) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return FALSE;

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons((short)port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    fd_set set;
    FD_ZERO(&set);
    FD_SET(sock, &set);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    BOOL open = FALSE;
    if (select(0, NULL, &set, NULL, &tv) > 0) {
        int err = 0;
        int len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        open = (err == 0);
    }

    closesocket(sock);
    return open;
}

void go(char* args, int len) {
    async_init(args, len);
    if (!async_is_initialized()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Async BOF not properly initialized. This BOF requires the async_bof.cna loader.");
        return;
    }

    datap parser;
    BeaconDataParse(&parser, args, len);

    char* target = BeaconDataExtract(&parser, NULL);
    if (!target || strlen(target) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: async_portscan <target> [start_port] [end_port] [timeout_ms]");
        BeaconPrintf(CALLBACK_ERROR, "[!]   target: IP address (e.g., 192.168.1.1)");
        BeaconPrintf(CALLBACK_ERROR, "[!]   start_port: First port to scan (default: 1)");
        BeaconPrintf(CALLBACK_ERROR, "[!]   end_port: Last port to scan (default: 1024)");
        BeaconPrintf(CALLBACK_ERROR, "[!]   timeout_ms: Connection timeout per port (default: 1000)");
        return;
    }

    int start_port = 1;
    int end_port = 1024;
    int timeout_ms = 1000;

    if (BeaconDataLength(&parser) > 0) start_port = BeaconDataInt(&parser);
    if (BeaconDataLength(&parser) > 0) end_port = BeaconDataInt(&parser);
    if (BeaconDataLength(&parser) > 0) timeout_ms = BeaconDataInt(&parser);

    if (start_port < 1) start_port = 1;
    if (end_port > 65535) end_port = 65535;
    if (start_port > end_port) {
        BeaconPrintf(CALLBACK_ERROR, "[!] start_port must be <= end_port");
        return;
    }

    WSADATA wsa = { 0 };
    WSAStartup(MAKEWORD(2, 2), &wsa);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Async Port Scanner started");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s", target);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Port range: %d - %d", start_port, end_port);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Timeout: %d ms", timeout_ms);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Waiting... (Use 'async_stop' to stop)");

    int open_count = 0;
    int scanned = 0;
    int total = end_port - start_port + 1;

    for (int port = start_port; port <= end_port; port++) {
        if (async_should_stop(0)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Scan stopped by user");
            break;
        }

        if (try_connect(target, port, timeout_ms)) {
            ASYNC_ALERT("[!] OPEN PORT: %s:%d", target, port);
            open_count++;
        }

        scanned++;
        if (scanned % 100 == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Progress: %d/%d ports scanned (%d open)", scanned, total, open_count);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scan complete: %d/%d ports open on %s", open_count, total, target);

    async_stopping();
    WSACleanup();
    async_stopped();
}
