#include "kii_core_init.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "kii_core_secure_socket.h"

static void logger_cb(const char* format, ...)
{
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
}

void kii_core_init(
        kii_core_t* kii,
        char* app_host,
        char* app_id,
        char* app_key,
        char* buff,
        size_t length)
{
    kii_http_context_t* http_ctx;
    memset(kii, 0x00, sizeof(kii_core_t));
    kii->app_id = app_id;
    kii->app_key = app_key;
    kii->app_host = app_host;

    http_ctx = &kii->http_context;
    http_ctx->buffer = buff;
    http_ctx->buffer_size = length;
    http_ctx->connect_cb = s_connect_cb;
    http_ctx->send_cb = s_send_cb;
    http_ctx->recv_cb = s_recv_cb;
    http_ctx->close_cb = s_close_cb;
    http_ctx->socket_context.app_context = NULL;

    kii->logger_cb = logger_cb;
}

