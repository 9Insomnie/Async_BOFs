#ifndef _ASYNC_PROTOCOL_H_
#define _ASYNC_PROTOCOL_H_

#define ASYNC_PROTOCOL_MAGIC      "\x00ASYNCPROTO\x00"
#define ASYNC_PROTOCOL_MAGIC_LEN 13

#define ASYNC_CMD_INIT      "INIT"
#define ASYNC_CMD_WAKEUP    "WAKEUP"
#define ASYNC_CMD_STOPPING  "STOPPING"
#define ASYNC_CMD_STOPPED   "STOPPED"
#define ASYNC_CMD_DATA      "DATA"
#define ASYNC_CMD_STOP_ACK  "STOP_ACK"

#define ASYNC_SEPARATOR     "\x00"

#define ASYNC_ARGS_PREFIX   "\x1ASTOP\x1A"

typedef enum {
    ASYNC_STATUS_OK = 0,
    ASYNC_STATUS_NOT_INITIALIZED,
    ASYNC_STATUS_INVALID_ARGS,
    ASYNC_STATUS_NO_STOP_EVENT,
    ASYNC_STATUS_BUFFER_TOO_SMALL,
    ASYNC_STATUS_UNKNOWN_CMD
} ASYNC_STATUS;

typedef struct {
    char* cmd;
    char* payload;
    int payload_len;
} ASYNC_MESSAGE;

int async_build_msg(char* out_buf, int buf_size, const char* cmd, const char* payload, int payload_len);

ASYNC_STATUS async_parse_msg(const char* msg_buf, int msg_len, ASYNC_MESSAGE* out_msg);

int async_parse_handle_from_args(char* args, int args_len);

int async_is_async_message(const char* data, int len);

int async_extract_payload(const char* data, int len, char* out_payload, int out_size);

#endif
