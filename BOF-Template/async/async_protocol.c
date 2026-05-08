#include "async_protocol.h"
#include <string.h>
#include <stdio.h>

int async_build_msg(char* out_buf, int buf_size, const char* cmd, const char* payload, int payload_len) {
    int magic_len = ASYNC_PROTOCOL_MAGIC_LEN;
    int cmd_len = (int)strlen(cmd);
    int sep_len = 1;

    int total_len = magic_len + cmd_len + sep_len;
    if (payload && payload_len > 0) {
        total_len += payload_len + sep_len;
    }

    if (buf_size < total_len + 1) {
        return -1;
    }

    char* p = out_buf;

    memcpy(p, ASYNC_PROTOCOL_MAGIC, magic_len);
    p += magic_len;

    memcpy(p, cmd, cmd_len);
    p += cmd_len;

    *p++ = '\0';

    if (payload && payload_len > 0) {
        memcpy(p, payload, payload_len);
        p += payload_len;
        *p++ = '\0';
    }

    return (int)(p - out_buf);
}

static int safe_strlen(const char* s, int max_len) {
    int len = 0;
    while (len < max_len && s[len] != '\0') {
        len++;
    }
    return len;
}

ASYNC_STATUS async_parse_msg(const char* msg_buf, int msg_len, ASYNC_MESSAGE* out_msg) {
    if (!msg_buf || !out_msg || msg_len < ASYNC_PROTOCOL_MAGIC_LEN) {
        return ASYNC_STATUS_INVALID_ARGS;
    }

    if (memcmp(msg_buf, ASYNC_PROTOCOL_MAGIC, ASYNC_PROTOCOL_MAGIC_LEN) != 0) {
        return ASYNC_STATUS_INVALID_ARGS;
    }

    const char* p = msg_buf + ASYNC_PROTOCOL_MAGIC_LEN;
    int remaining = msg_len - ASYNC_PROTOCOL_MAGIC_LEN;

    int cmd_len = safe_strlen(p, remaining);
    if (cmd_len == 0 || cmd_len >= 32) {
        return ASYNC_STATUS_INVALID_ARGS;
    }

    out_msg->cmd = (char*)p;

    p += cmd_len + 1;
    remaining -= cmd_len + 1;

    if (remaining > 0) {
        out_msg->payload = (char*)p;
        out_msg->payload_len = safe_strlen(p, remaining);
    } else {
        out_msg->payload = NULL;
        out_msg->payload_len = 0;
    }

    return ASYNC_STATUS_OK;
}

int async_parse_handle_from_args(char* args, int args_len) {
    if (!args || args_len < 20) {
        return 0;
    }

    const char* prefix = ASYNC_ARGS_PREFIX;
    int prefix_len = (int)strlen(prefix);

    for (int i = 0; i <= args_len - prefix_len - 4; i++) {
        if (memcmp(args + i, prefix, prefix_len) == 0) {
            int handle_val = 0;
            int offset = i + prefix_len;

            for (int j = 0; j < 16 && offset + j < args_len; j++) {
                char c = args[offset + j];
                if (c >= '0' && c <= '9') {
                    handle_val = handle_val * 16 + (c - '0');
                } else if (c >= 'a' && c <= 'f') {
                    handle_val = handle_val * 16 + (c - 'a' + 10);
                } else if (c >= 'A' && c <= 'F') {
                    handle_val = handle_val * 16 + (c - 'A' + 10);
                } else {
                    break;
                }
            }

            return handle_val;
        }
    }

    return 0;
}

int async_is_async_message(const char* data, int len) {
    if (!data || len < ASYNC_PROTOCOL_MAGIC_LEN) {
        return 0;
    }
    return memcmp(data, ASYNC_PROTOCOL_MAGIC, ASYNC_PROTOCOL_MAGIC_LEN) == 0;
}

int async_extract_payload(const char* data, int len, char* out_payload, int out_size) {
    ASYNC_MESSAGE msg;
    if (async_parse_msg(data, len, &msg) != ASYNC_STATUS_OK) {
        return -1;
    }

    if (!msg.payload || msg.payload_len <= 0) {
        return -1;
    }

    if (out_payload && out_size > 0) {
        int copy_len = (msg.payload_len < out_size - 1) ? msg.payload_len : out_size - 1;
        memcpy(out_payload, msg.payload, copy_len);
        out_payload[copy_len] = '\0';
    }

    return msg.payload_len;
}
