#include <gt202_kii_adapter.h>

#include <kii.h>

#include <main.h>
#include <atheros_stack_offload.h>
#include "atheros_wifi.h"
#include "atheros_wifi_api.h"

#define CONNECT_SSL 0

#define BUFF_SIZE 256

typedef enum prv_ssl_state_t {
    PRV_SSL_STATE_IDLE,
    PRV_SSL_STATE_CONNECT,
    PRV_SSL_STATE_SEND,
    PRV_SSL_STATE_RECV,
    PRV_SSL_STATE_CLOSE,
} prv_ssl_state_t;

typedef struct context_t
{
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    int sock;
    char* buff;
    size_t buff_size;
    char host[256];
    prv_ssl_state_t state;
    int last_chunk;
    int sent_size;
    int received_size;
} context_t;

static kii_http_client_code_t prv_ssl_connect(void* app_context, const char* host)
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
#if 0
        else
        {
            if(dnsRespInfo.dns_names[0] != 0)
            {
               printf("host: name=%s\r\n", dnsRespInfo.dns_names);
            } 	    
            printf("addrtype %d \r\n", A_CPU2LE32(dnsRespInfo.h_addrtype));
            printf("length %d \r\n", A_CPU2LE32(dnsRespInfo.h_length));
            for (int i = 0; i < dnsRespInfo.ipaddrs; ++i)
            {
                A_UINT32 addr = A_CPU2BE32(dnsRespInfo.ipaddrs_list[i]);
                printf("addr[%d]:%d.%d.%d.%d \r\n", i, getByte(3, addr),
                        getByte(2, addr), getByte(1, addr), getByte(0, addr));
            }
        }
#endif
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
    app_time_delay(5);

    memset(&hostAddr, 0x00, sizeof(hostAddr));
    hostAddr.sin_family = ATH_AF_INET;
    hostAddr.sin_addr = A_BE2CPU32(dnsRespInfo.ipaddrs_list[0]);
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
    app_time_delay(1000);
#endif

    ctx->sock = sock;
    ctx->ssl = ssl;
    ctx->ssl_ctx = ssl_ctx;
    return KII_HTTPC_OK;
}

static kii_http_client_code_t prv_ssl_send(void* app_context, const char* send_buff, int buff_length)
{
    context_t* ctx = (context_t*)app_context;
    char* buff = CUSTOM_ALLOC(buff_length);

    memcpy(buff, send_buff, buff_length);
#if CONNECT_SSL
    int ret = SSL_write(ctx->ssl, buff, buff_length);
#else
    int ret = t_send(handle, ctx->sock, buff, buff_length, 0);
#endif

    CUSTOM_FREE(buff);

    if (ret > 0) {
        return KII_HTTPC_OK;
    } else {
        printf("failed to send\n");
        return KII_HTTPC_FAIL;
    }
}

static kii_http_client_code_t prv_ssl_recv(void* app_context, char* recv_buff, int length_to_read, int* out_actual_length)
{
    int ret = KII_HTTPC_FAIL;
    int res;
    int received;
    int total = 0;
    char *pBuf = NULL;
    context_t* ctx = (context_t*)app_context;
    do
    {
        res = t_select((void *)handle, ctx->sock, 1000);
        if (res == A_OK)
        {
#if ZERO_COPY
#if CONNECT_SSL
            received = SSL_read(ctx->ssl, (void**)&pBuf, length_to_read);
#else
            received = t_recv(handle, ctx->sock, (void**)&pBuf, length_to_read, 0);
#endif
            if(received > 0)
            {
                memcpy(recv_buff, pBuf, received);
                zero_copy_free(pBuf);
                total = received;
                break;
            }
#else
#if CONNECT_SSL
            received = SSL_read(ssl, recv_buff, length_to_read);
#else
            received = t_recv(handle, ctx->sock, recv_buff, length_to_read, 0);
#endif
            if(received > 0)
            {
                total = received;
                break;
            }
#endif
        }
    } while (res == A_OK);

    if (total >  0) {
        *out_actual_length = total;
        return KII_HTTPC_OK;
    } else {
        printf("failed to receive:\n");
        // TOOD: could be 0 on success?
        *out_actual_length = 0;
        return KII_HTTPC_FAIL;
    }
}


static kii_http_client_code_t prv_ssl_close(void* app_context)
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
    strcpy(ctx->host, host);
    // TODO: prevent overflow.
    //sprintf(reqBuff, "%s https://%s/%s HTTP/1.1\r\n", method, host, path);
    sprintf(reqBuff, "%s /%s HTTP/1.1\r\nhost:%s\r\n", method, path, host);

    return KII_HTTPC_OK;
}

kii_http_client_code_t
    header_cb(
        void* http_context,
        const char* key,
        const char* value)
{
    // TODO: prevent overflow.
    char* reqBuff = ((context_t*)http_context)->buff;
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
    // TODO: prevent overflow.
    char* reqBuff = ((context_t*)http_context)->buff;
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
        case PRV_SSL_STATE_IDLE:
            ctx->state = PRV_SSL_STATE_CONNECT;
            return KII_HTTPC_AGAIN;
        case PRV_SSL_STATE_CONNECT:
            res = prv_ssl_connect(ctx, ctx->host);
            if (res == KII_HTTPC_OK) {
                ctx->state = PRV_SSL_STATE_SEND;
                return KII_HTTPC_AGAIN;
            } else if (res == KII_HTTPC_AGAIN) {
                return KII_HTTPC_AGAIN;
            } else {
                ctx->state = PRV_SSL_STATE_IDLE;
                return KII_HTTPC_FAIL;
            }
        case PRV_SSL_STATE_SEND:
        {
            int size = BUFF_SIZE;
            int remain = strlen(ctx->buff) - ctx->sent_size;
            if (remain < size) {
                size = remain;
                ctx->last_chunk = 1;
            }
            char* sendBuff = ctx->buff + ctx->sent_size;
            res = prv_ssl_send(
                    ctx,
                    sendBuff,
                    size);
            if (res == KII_HTTPC_OK) {
                ctx->sent_size += size;
                if (ctx->last_chunk > 0) {
                    ctx->state = PRV_SSL_STATE_RECV;
                }
                return KII_HTTPC_AGAIN;
            } else if(res == KII_HTTPC_AGAIN) {
                return KII_HTTPC_AGAIN;
            } else {
                ctx->state = PRV_SSL_STATE_IDLE;
                return KII_HTTPC_FAIL;
            }
        }
        case PRV_SSL_STATE_RECV:
        {
            int actualLength = 0;
            char* buffPtr = ctx->buff + ctx->received_size;
            if (ctx->received_size == 0) {
                memset(ctx->buff, 0x00, ctx->buff_size);
            }
            res = prv_ssl_recv(ctx, buffPtr, BUFF_SIZE, &actualLength);
            if (res == KII_HTTPC_OK) {
                ctx->received_size += actualLength;
                if (actualLength < BUFF_SIZE) {
                    ctx->state = PRV_SSL_STATE_CLOSE;
                }
                return KII_HTTPC_AGAIN;
            } else if (res == KII_HTTPC_AGAIN) {
                return KII_HTTPC_AGAIN;
            } else {
                ctx->state = PRV_SSL_STATE_IDLE;
                return KII_HTTPC_FAIL;
            }
        }
        case PRV_SSL_STATE_CLOSE:
        {
            res = prv_ssl_close(ctx);
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
                ctx->state = PRV_SSL_STATE_IDLE;
                return KII_HTTPC_OK;
            } else if (res == KII_HTTPC_AGAIN) {
                return KII_HTTPC_AGAIN;
            } else {
                ctx->state = PRV_SSL_STATE_IDLE;
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

void parse_response(char* resp_body)
{
    /* TODO: implement */
}

static void init(kii_t* kii, context_t* ctx, char* buff, int buff_length)
{
    memset(kii, 0x00, sizeof(kii_t));
    //kii->app_id = "9ab34d8b";
    //kii->app_key = "7a950d78956ed39f3b0815f0f001b43b";
    //kii->app_host = "api-jp.kii.com";
    kii->app_id = "84fff36e";
    kii->app_key = "e45fcc2d31d6aca675af639bc5f04a26";
    kii->app_host = "api-development-jp.internal.kii.com";
    kii->buffer = buff;
    kii->buffer_size = buff_length;

    kii->http_context = ctx;
    kii->http_set_request_line_cb = request_line_cb;
    kii->http_set_header_cb = header_cb;
    kii->http_set_body_cb = body_cb;
    kii->http_execute_cb = execute_cb;
    kii->logger_cb = logger_cb;

    memset(ctx, 0x00, sizeof(context_t));
    /* share the request and response buffer.*/
    ctx->buff = buff;
    ctx->buff_size = buff_length;
}

static void set_author(kii_t* kii, kii_author_t* author)
{
    memset(author, 0x00, sizeof(kii_author_t));
    //author->author_id = "th.34cc40051321-0eab-4e11-f71c-09eb58f4";
    //author->access_token = "rYZCxdQ2z1pLwt0su2mjrzUezCqCguaawIwZxMyca7o";
    author->author_id = "th.53ae324be5a0-26f8-4e11-a13c-03da6fb2";
    author->access_token = "ablTGrnsE20rSRBFKPnJkWyTaeqQ50msqUizvR_61hU";
    kii->author = author;
}

static void init_bucket(kii_bucket_t* bucket) {
    memset(bucket, 0x00, sizeof(kii_bucket_t));
    bucket->scope = KII_SCOPE_THING;
    //bucket->scope_id = "th.34cc40051321-0eab-4e11-f71c-09eb58f4";
    bucket->scope_id = "th.53ae324be5a0-26f8-4e11-a13c-03da6fb2";
    bucket->bucket_name = "myBucket";
}

static void init_topic(kii_topic_t* topic) {
    memset(topic, 0x00, sizeof(kii_topic_t));
    topic->scope = KII_SCOPE_THING;
    //topic->scope_id = "th.34cc40051321-0eab-4e11-f71c-09eb58f4";
    topic->scope_id = "th.53ae324be5a0-26f8-4e11-a13c-03da6fb2";
    topic->topic_name = "myTopic";
}

static void print_response(kii_t* kii)
{
    printf("========response========\n");
    printf("%s\n", kii->buffer);
    printf("========response========\n");
    printf("response_code: %d\n", kii->response_code);
    printf("response_body:\n%s\n", kii->response_body);
}

static int register_thing(kii_t* kii)
{
    int ret = 0;
    kii_state_t state;
    kii_error_code_t err;
    char *thingData = malloc(1024);
    
    /* Prepare Thing Data */
    memset(thingData, 0x00, 1024);
    sprintf(thingData,
            "{\"_vendorThingID\":\"%d\", \"_password\":\"1234\"}",
            time(NULL));
    /* Register Thing */
    err = kii_register_thing(kii, thingData);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        ret = 1;
        goto END_FUNC;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        ret = 1;
        goto END_FUNC;
    }
    print_response(kii);
    parse_response(kii->response_body);

END_FUNC:
    free(thingData);
    return ret;
}

static int create_new_object(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;
    
    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_create_new_object(
            kii,
            &bucket,
            "{}",
            NULL);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int create_new_object_with_id(kii_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;
    
    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_create_new_object_with_id(
            kii,
            &bucket,
            id,
            "{}",
            NULL);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int patch_object(kii_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_patch_object(
            kii,
            &bucket,
            id,
            "{}",
            NULL);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int replace_object(kii_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_replace_object(
            kii,
            &bucket,
            id,
            "{}",
            NULL);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int get_object(kii_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_get_object(
            kii,
            &bucket,
            id);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int delete_object(kii_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_delete_object(
            kii,
            &bucket,
            id);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int subscribe_bucket(kii_t* kii, const char* bucket_name)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_subscribe_bucket(
            kii,
            &bucket);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int unsubscribe_bucket(kii_t* kii, const char* bucket_name)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_unsubscribe_bucket(
            kii,
            &bucket);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int create_topic(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    init_topic(&topic);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_create_topic(
            kii,
            &topic);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int delete_topic(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    init_topic(&topic);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_delete_topic(
            kii,
            &topic);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int subscribe_topic(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    init_topic(&topic);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_subscribe_topic(
            kii,
            &topic);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int unsubscribe_topic(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    init_topic(&topic);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_unsubscribe_topic(
            kii,
            &topic);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int install_push(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_author_t author;
    set_author(kii, &author);

    err = kii_install_thing_push(
            kii,
            KII_FALSE);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int get_endpoint(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_author_t author;
    set_author(kii, &author);

    err = kii_get_mqtt_endpoint(
            kii,
            "fja58hhba7xoj4mv11ytxpl92");
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

int kii_main(int argc, char *argv[])
{
    int ret = A_ERROR;
    context_t *ctx = NULL;
    kii_t *kii = NULL;
    kii_state_t state;
    kii_error_code_t err;
    char *buff = NULL;

    if (argc < 3)
    {
        return A_ERROR;
    }

    kii = malloc(sizeof(kii_t));
    ctx = malloc(sizeof(context_t));
    buff = malloc(4096);

    init(kii, ctx, buff, 4096);

    if(ATH_STRCMP(argv[2], "register") == 0)
    {
        if (register_thing(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "new-object") == 0)
    {
        if (create_new_object(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "new-object-with-id") == 0)
    {
        if (create_new_object_with_id(kii, "my_object") == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "patch-object") == 0)
    {
        if (patch_object(kii, "my_object") == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "replace-object") == 0)
    {
        if (replace_object(kii, "my_object") == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "get-object") == 0)
    {
        if (get_object(kii, "my_object") == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "delete-object") == 0)
    {
        if (delete_object(kii, "my_object") == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "subscribe-bucket") == 0)
    {
        if (subscribe_bucket(kii, "myBucket") == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "unsubscribe-bucket") == 0)
    {
        if (unsubscribe_bucket(kii, "myBucket") == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "create-topic") == 0)
    {
        if (create_topic(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "delete-topic") == 0)
    {
        if (delete_topic(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "subscribe-topic") == 0)
    {
        if (subscribe_topic(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "unsubscribe-topic") == 0)
    {
        if (unsubscribe_topic(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "install-push") == 0)
    {
        if (install_push(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[2], "get-endpoint") == 0)
    {
        if (get_endpoint(kii) == 0)
        {
            ret = A_OK;
        }
    }

    free(kii);
    free(buff);
    free(ctx);
    return ret;
}

