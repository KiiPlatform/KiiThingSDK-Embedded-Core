#include "gt202_kii_adapter.h"

#include "prv_kii_setting.h"

#define BUFF_SIZE 256

extern kii_http_client_code_t prv_recv(
        void* app_context,
        char* recv_buff,
        int length_to_read,
        int* out_actual_length);

kii_http_client_code_t prv_close(void* app_context);

static kii_http_client_code_t prv_connect(void* app_context, const char* host)
{
    int ret;
    DNC_CFG_CMD dnsCfg;
    DNC_RESP_INFO dnsRespInfo;
    SOCKADDR_T hostAddr;
    A_UINT32 sock;
    SSL *ssl = NULL;
    SSL_CTX *ssl_ctx = NULL;
    context_t *ctx = (context_t*)app_context;

    memset(&dnsRespInfo, 0, sizeof(dnsRespInfo));
    /*Check if driver is loaded*/
    if(IS_DRIVER_READY != A_OK){
        return KII_HTTPC_FAIL;
    }

    // resolve the IP address of the host
    if (0 == ath_inet_aton(host, &dnsRespInfo.ipaddrs_list[0]))
    {
        if (strlen(host) >= sizeof(dnsCfg.ahostname))
        {
            printf("GetERROR: host name too long\n");
            return KII_HTTPC_FAIL;
        }
        strcpy((char*)dnsCfg.ahostname, host);
        dnsCfg.domain = ATH_AF_INET;
        dnsCfg.mode =  RESOLVEHOSTNAME;
        if (A_OK != custom_ip_resolve_hostname(handle, &dnsCfg, &dnsRespInfo))
        {
            printf("GetERROR: Unable to resolve host name\r\n");
            return KII_HTTPC_FAIL;
        }
        dnsRespInfo.ipaddrs_list[0] = A_BE2CPU32(dnsRespInfo.ipaddrs_list[0]);
    }

#if CONNECT_SSL
    ssl_ctx = SSL_ctx_new(SSL_CLIENT, 4500, 2000, 0);
    if (ssl_ctx == NULL){
        printf("failed to init ssl context.\n");
        return KII_HTTPC_FAIL;
    }
#endif

    sock = t_socket((void *)handle, ATH_AF_INET, SOCK_STREAM_TYPE, 0);
    if (sock < 0) {
        printf("failed to init socket.\n");
        return KII_HTTPC_FAIL;
    }

    memset(&hostAddr, 0x00, sizeof(hostAddr));
    hostAddr.sin_family = ATH_AF_INET;
    hostAddr.sin_addr = dnsRespInfo.ipaddrs_list[0];
#if CONNECT_SSL
    hostAddr.sin_port = 443;
#else
    hostAddr.sin_port = 80;
#endif

    if (t_connect((void *)handle, sock, &hostAddr, sizeof(hostAddr)) == A_ERROR){
        printf("failed to connect socket.\n");
        return KII_HTTPC_FAIL;
    }

#if CONNECT_SSL
    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL){
        printf("failed to init ssl.\n");
        return KII_HTTPC_FAIL;
    }

    ret = SSL_set_fd(ssl, sock);
    if (ret < 0){
        printf("failed to set fd: %d\n", ret);
        return KII_HTTPC_FAIL;
    }

    ret = SSL_connect(ssl);
    if (ret < 0) {
        printf("failed to connect: %d\n", ret);
        return KII_HTTPC_FAIL;
    }
#endif

    ctx->sock = sock;
    ctx->ssl = ssl;
    ctx->ssl_ctx = ssl_ctx;
    return KII_HTTPC_OK;
}

static kii_http_client_code_t prv_send(void* app_context, const char* send_buff, int buff_length)
{
    context_t* ctx = (context_t*)app_context;
    char* buff = CUSTOM_ALLOC(buff_length);

    memcpy(buff, send_buff, buff_length);
#if CONNECT_SSL
    int ret = SSL_write(ctx->ssl, buff, buff_length);
#else
    int ret = t_send(handle, ctx->sock, (uint_8 *)buff, buff_length, 0);
#endif

    CUSTOM_FREE(buff);

    if (ret > 0) {
        return KII_HTTPC_OK;
    } else {
        printf("failed to send\n");
        prv_close(app_context);
        return KII_HTTPC_FAIL;
    }
}

kii_http_client_code_t prv_close(void* app_context)
{
    context_t* ctx = (context_t*)app_context;
#if CONNECT_SSL
    if (ctx->ssl != NULL)
    {
        SSL_shutdown(ctx->ssl);
    }
    if (ctx->ssl_ctx != NULL)
    {
        SSL_ctx_free(ctx->ssl_ctx);
    }
#endif
    if (ctx->sock > 0)
    {
        t_shutdown(handle, ctx->sock);
    }
    return KII_HTTPC_OK;
}

/* HTTP Callback functions */
kii_http_client_code_t
    request_line_cb(
        void* http_context,
        const char* method,
        const char* host,
        const char* path)
{
    context_t* ctx = (context_t*)http_context;
    char* reqBuff = ctx->buff;
    int hostLen = strlen(host);
    if (hostLen < sizeof(ctx->host)) {
        strcpy(ctx->host, host);
    } else {
        return KII_HTTPC_FAIL;
    }
    if (ctx->buff_size < 21 + strlen(method) + strlen(path) + hostLen) {
        return KII_HTTPC_FAIL;
    }
    sprintf(reqBuff, "%s /%s HTTP/1.1\r\nhost:%s\r\n", method, path, host);

    return KII_HTTPC_OK;
}

kii_http_client_code_t
    header_cb(
        void* http_context,
        const char* key,
        const char* value)
{
    context_t* ctx = (context_t*)http_context;
    char* reqBuff = ctx->buff;
    if (ctx->buff_size < strlen(reqBuff) + 4 + strlen(key) + strlen(value)) {
        return KII_HTTPC_FAIL;
    }
    strcat(reqBuff, key);
    strcat(reqBuff, ":");
    strcat(reqBuff, value);
    strcat(reqBuff, "\r\n");
    return KII_HTTPC_OK;
}

kii_http_client_code_t
    body_cb(
        void* http_context,
        const char* body_data)
{
    context_t* ctx = (context_t*)http_context;
    char* reqBuff = ctx->buff;
    int body_len = (body_data != NULL) ? strlen(body_data) : 0;
    if (ctx->buff_size < strlen(reqBuff) + 3 + body_len) {
        return KII_HTTPC_FAIL;
    }
    strcat(reqBuff, "\r\n");
    if (body_data != NULL) {
        strcat(reqBuff, body_data);
    }
    return KII_HTTPC_OK;
}

kii_http_client_code_t
    execute_cb(
        void* http_context,
        int* response_code,
        char** response_body)
{
    context_t* ctx = (context_t*)http_context;
    kii_http_client_code_t res;
    switch (ctx->state) {
        case PRV_STATE_IDLE:
            ctx->sent_size = 0;
            ctx->last_chunk = 0;
            ctx->received_size = 0;
            ctx->state = PRV_STATE_CONNECT;
            return KII_HTTPC_AGAIN;
        case PRV_STATE_CONNECT:
            res = prv_connect(ctx, ctx->host);
            if (res == KII_HTTPC_OK) {
                ctx->state = PRV_STATE_SEND;
                return KII_HTTPC_AGAIN;
            } else if (res == KII_HTTPC_AGAIN) {
                return KII_HTTPC_AGAIN;
            } else {
                prv_close(ctx);
                ctx->state = PRV_STATE_IDLE;
                return KII_HTTPC_FAIL;
            }
        case PRV_STATE_SEND:
        {
            int size = BUFF_SIZE;
            int remain = strlen(ctx->buff) - ctx->sent_size;
            if (remain < size) {
                size = remain;
                ctx->last_chunk = 1;
            }
            char* sendBuff = ctx->buff + ctx->sent_size;
            res = prv_send(
                    ctx,
                    sendBuff,
                    size);
            if (res == KII_HTTPC_OK) {
                ctx->sent_size += size;
                if (ctx->last_chunk > 0) {
                    ctx->state = PRV_STATE_RECV;
                }
                return KII_HTTPC_AGAIN;
            } else if(res == KII_HTTPC_AGAIN) {
                return KII_HTTPC_AGAIN;
            } else {
                prv_close(ctx);
                ctx->state = PRV_STATE_IDLE;
                return KII_HTTPC_FAIL;
            }
        }
        case PRV_STATE_RECV:
        {
            int actualLength = 0;
            char* buffPtr = ctx->buff + ctx->received_size;
            if (ctx->received_size == 0) {
                memset(ctx->buff, 0x00, ctx->buff_size);
            }
            res = prv_recv(ctx, buffPtr, BUFF_SIZE, &actualLength);
            if (res == KII_HTTPC_OK) {
                ctx->received_size += actualLength;
                if (actualLength < BUFF_SIZE) {
                    ctx->state = PRV_STATE_CLOSE;
                }
                return KII_HTTPC_AGAIN;
            } else if (res == KII_HTTPC_AGAIN) {
                return KII_HTTPC_AGAIN;
            } else {
                prv_close(ctx);
                ctx->state = PRV_STATE_IDLE;
                return KII_HTTPC_FAIL;
            }
        }
        case PRV_STATE_CLOSE:
        {
            res = prv_close(ctx);
            if (res == KII_HTTPC_OK) {
                /* parse status code */
                char* statusPtr = strstr(ctx->buff, "HTTP/1.1 ");
                int numCode = 0;
                char* bodyPtr = NULL;
                if (statusPtr != NULL) {
                    char c_status_code[4];
                    c_status_code[3] = '\0';
                    statusPtr += strlen("HTTP/1.1 ");
                    memcpy(c_status_code, statusPtr, 3);
                    numCode = atoi(c_status_code);
                    *response_code = numCode;
                }
                /* set body pointer */
                bodyPtr = strstr(ctx->buff, "\r\n\r\n");
                if (bodyPtr != NULL) {
                    bodyPtr += 4;
                }
                *response_body = bodyPtr;
                ctx->state = PRV_STATE_IDLE;
                return KII_HTTPC_OK;
            } else if (res == KII_HTTPC_AGAIN) {
                return KII_HTTPC_AGAIN;
            } else {
                ctx->state = PRV_STATE_IDLE;
                return KII_HTTPC_FAIL;
            }
        }
    }

    return KII_HTTPC_OK;
}

void logger_cb(const char* format, ...)
{
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
}
