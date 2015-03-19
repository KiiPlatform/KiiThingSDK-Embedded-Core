#ifndef _gt202_kii_adapter
#define _gt202_kii_adapter

#include <kii.h>

#include <main.h>

typedef enum prv_state {
    PRV_STATE_IDLE,
    PRV_STATE_CONNECT,
    PRV_STATE_SEND,
    PRV_STATE_RECV,
    PRV_STATE_CLOSE,
} prv_state_t;

typedef struct context
{
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    int sock;
    char* buff;
    size_t buff_size;
    char host[256];
    prv_state_t state;
    int last_chunk;
    int sent_size;
    int received_size;
} context_t;

/* HTTP Callback functions */

kii_http_client_code_t request_line_cb(
        void* http_context,
        const char* method,
        const char* host,
        const char* path);

kii_http_client_code_t header_cb(
        void* http_context,
        const char* key,
        const char* value);

kii_http_client_code_t body_cb(
        void* http_context,
        const char* body_data);

kii_http_client_code_t execute_cb(
        void* http_context,
        int* response_code,
        char** response_body);

void logger_cb(const char* format, ...);

#endif

