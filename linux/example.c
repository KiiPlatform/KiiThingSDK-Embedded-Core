#include "../kii_core.h"
#include "example.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <getopt.h>

#define BUFF_SIZE 256

typedef enum prv_ssl_state_t {
    PRV_SSL_STATE_IDLE,
    PRV_SSL_STATE_CONNECT,
    PRV_SSL_STATE_SEND,
    PRV_SSL_STATE_RECV,
    PRV_SSL_STATE_CLOSE
} prv_ssl_state_t;

typedef struct context_t
{
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    int sock;
    char host[256];
    prv_ssl_state_t state;
    int last_chunk;
    int sent_size;
    int received_size;
} context_t;

static kii_http_client_code_t prv_ssl_connect(kii_http_context_t* http_context,
        const char* host)
{
    int sock, ret;
    struct hostent *servhost;
    struct sockaddr_in server;
    struct servent *service;
    context_t* ctx = (context_t*)(http_context->app_context);
    SSL *ssl;
    SSL_CTX *ssl_ctx;

    printf("host: %s\n", host);
    
    servhost = gethostbyname(host);
    if (servhost == NULL) {
        printf("failed to get host.\n");
        return KII_HTTPC_FAIL;
    }
    memset(&server, 0x00, sizeof(server));
    server.sin_family = AF_INET;
    /* More secure. */
    memcpy(&(server.sin_addr), servhost->h_addr, servhost->h_length);

    /* Get Port number */
    service = getservbyname("https", "tcp");
    if (service != NULL) {
        server.sin_port = service->s_port;
    } else {
        server.sin_port = htons(443);
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("failed to init socket.\n");
        return KII_HTTPC_FAIL;
    }

    if (connect(sock, (struct sockaddr*) &server, sizeof(server)) == -1 ){
        printf("failed to connect socket.\n");
        return KII_HTTPC_FAIL;
    }

    SSL_library_init();
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL){
        printf("failed to init ssl context.\n");
        return KII_HTTPC_FAIL;
    }

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL){
        printf("failed to init ssl.\n");
        return KII_HTTPC_FAIL;
    }

    ret = SSL_set_fd(ssl, sock);
    if (ret == 0){
        printf("failed to set fd.\n");
        return KII_HTTPC_FAIL;
    }

    ret = SSL_connect(ssl);
    if (ret != 1) {
        int sslErr= SSL_get_error(ssl, ret);
        char sslErrStr[120];
        ERR_error_string_n(sslErr, sslErrStr, 120);
        printf("failed to connect: %s\n", sslErrStr);
        return KII_HTTPC_FAIL;
    }
    ctx->sock = sock;
    ctx->ssl = ssl;
    ctx->ssl_ctx = ssl_ctx;
    return KII_HTTPC_OK;
}

static kii_http_client_code_t prv_ssl_send(kii_http_context_t* http_context,
        const char* send_buff, int buff_length)
{
    context_t* ctx = (context_t*)http_context->app_context;
    int ret = SSL_write(ctx->ssl, send_buff, buff_length);
    if (ret > 0) {
        return KII_HTTPC_OK;
    } else {
        printf("failed to send\n");
        return KII_HTTPC_FAIL;
    }
}

static kii_http_client_code_t prv_ssl_recv(kii_http_context_t* http_context,
        char* recv_buff, int length_to_read, int* out_actual_length)
{
    context_t* ctx = (context_t*)http_context->app_context;
    int ret = SSL_read(ctx->ssl, recv_buff, length_to_read);
    if (ret > 0) {
        *out_actual_length = ret;
        return KII_HTTPC_OK;
    } else {
        printf("failed to receive:\n");
        /* TOOD: could be 0 on success? */
        *out_actual_length = 0;
        return KII_HTTPC_FAIL;
    }
}


static kii_http_client_code_t prv_ssl_close(kii_http_context_t* http_context)
{
    context_t* ctx = (context_t*)http_context->app_context;
    int ret = SSL_shutdown(ctx->ssl);
    if (ret != 1) {
        int sslErr = SSL_get_error(ctx->ssl, ret);
        if (sslErr == SSL_ERROR_SYSCALL) {
            /* This is OK.*/
            /* See https://www.openssl.org/docs/ssl/SSL_shutdown.html */
            ret = 1;
        } else {
            char sslErrStr[120];
            ERR_error_string_n(sslErr, sslErrStr, 120);
            printf("failed to shutdown: %s\n", sslErrStr);
        }
    }
    close(ctx->sock);
    SSL_free(ctx->ssl);
    SSL_CTX_free(ctx->ssl_ctx);
    if (ret != 1) {
        printf("failed to close:\n");
        return KII_HTTPC_FAIL;
    }
    return KII_HTTPC_OK;
}

/* HTTP Callback functions */
kii_http_client_code_t
    request_line_cb(
        kii_http_context_t* http_context,
        const char* method,
        const char* host,
        const char* path)
{
    char* reqBuff;
    context_t* ctx;

    ctx = (context_t*)http_context->app_context;
    strncpy(ctx->host, host, strlen(host));

    reqBuff = http_context->buffer;
    /* TODO: prevent overflow. */
    sprintf(reqBuff, "%s https://%s/%s HTTP/1.1\r\n", method, host, path);

    return KII_HTTPC_OK;
}

kii_http_client_code_t
    header_cb(
        kii_http_context_t* http_context,
        const char* key,
        const char* value)
{
    /* TODO: prevent overflow. */
    char* reqBuff = http_context->buffer;
    strcat(reqBuff, key);
    strcat(reqBuff, ":");
    strcat(reqBuff, value);
    strcat(reqBuff, "\r\n");
    return KII_HTTPC_OK;
}

kii_http_client_code_t
    body_cb(
        kii_http_context_t* http_context,
        const char* body_data)
{
    /* TODO: prevent overflow. */
    char* reqBuff = http_context->buffer;
    strcat(reqBuff, "\r\n");
    if (body_data != NULL) {
        strcat(reqBuff, body_data);
    }
    return KII_HTTPC_OK;
}

kii_http_client_code_t
    execute_cb(
        kii_http_context_t* http_context,
        int* response_code,
        char** response_body)
{
    context_t* ctx;
    kii_http_client_code_t res;

    ctx = (context_t*)http_context->app_context;
    printf("client state: %d\n", ctx->state);
    switch (ctx->state) {
        case PRV_SSL_STATE_IDLE:
            ctx->sent_size = 0;
            ctx->last_chunk = 0;
            ctx->received_size = 0;
            ctx->state = PRV_SSL_STATE_CONNECT;
            return KII_HTTPC_AGAIN;
        case PRV_SSL_STATE_CONNECT:
            res = prv_ssl_connect(http_context, ctx->host);
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
            char* sendBuff = NULL;
            int size = BUFF_SIZE;
            int remain = strlen(http_context->buffer) - ctx->sent_size;
            if (remain < size) {
                size = remain;
                ctx->last_chunk = 1;
            }
            sendBuff = http_context->buffer + ctx->sent_size;
            res = prv_ssl_send(
                    http_context,
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
            char* buffPtr = http_context->buffer + ctx->received_size;
            if (ctx->received_size == 0) {
                memset(http_context->buffer, 0x00, http_context->buffer_size);
            }
            res = prv_ssl_recv(http_context, buffPtr, BUFF_SIZE, &actualLength);
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
            res = prv_ssl_close(http_context);
            if (res == KII_HTTPC_OK) {
                /* parse status code */
                char* statusPtr = strstr(http_context->buffer, "HTTP/1.1 ");
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
                bodyPtr = strstr(http_context->buffer, "\r\n\r\n");
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

void init(kii_core_t* kii, char* buff, context_t* ctx) {
    kii_http_context_t* http_ctx;
    memset(kii, 0x00, sizeof(kii_core_t));
    kii->app_id = (char*)EX_APP_ID;
    kii->app_key = (char*)EX_APP_KEY;
    kii->app_host = (char*)EX_APP_HOST;

    memset(ctx, 0x00, sizeof(context_t));
    http_ctx = &kii->http_context;
    http_ctx->app_context = ctx;
    http_ctx->buffer = buff;
    http_ctx->buffer_size = EX_BUFFER_SIZE;

    kii->http_set_request_line_cb = request_line_cb;
    kii->http_set_header_cb = header_cb;
    kii->http_set_body_cb = body_cb;
    kii->http_execute_cb = execute_cb;
    kii->logger_cb = logger_cb;

}

static void set_author(kii_core_t* kii, kii_author_t* author)
{
    memset(author, 0x00, sizeof(kii_author_t));
    strncpy(author->author_id, (char*)EX_THING_ID, 128);
    strncpy(author->access_token, (char*)EX_ACCESS_TOKEN, 128);
    kii->author = *author;
}

static void init_bucket(kii_bucket_t* bucket) {
    memset(bucket, 0x00, sizeof(kii_bucket_t));
    bucket->scope = KII_SCOPE_THING;
    bucket->scope_id = (char*)EX_THING_ID;
    bucket->bucket_name = (char*)EX_BUCKET_NAME;
}

static void init_topic(kii_topic_t* topic) {
    memset(topic, 0x00, sizeof(kii_topic_t));
    topic->scope = KII_SCOPE_THING;
    topic->scope_id = (char*)EX_THING_ID;
    topic->topic_name = (char*)EX_TOPIC_NAME;
}

static void print_request(kii_core_t* kii)
{
    printf("========request========\n");
    printf("%s\n", kii->http_context.buffer);
    printf("========request========\n");
}

static void print_response(kii_core_t* kii)
{
    printf("========response========\n");
    printf("%s\n", kii->http_context.buffer);
    printf("========response========\n");
    printf("response_code: %d\n", kii->response_code);
    printf("response_body:\n%s\n", kii->response_body);
}

static int register_thing(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;
    pid_t pid;
    char thingData[1024];
    
    /* Prepare Thing Data */
    memset(thingData, 0x00, 1024);
    pid = getpid();
    sprintf(thingData,
            "{\"_vendorThingID\":\"%d\", \"_password\":\"1234\"}",
            pid);
    /* Register Thing */
    err = kii_core_register_thing(kii, thingData);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int thing_authentication(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    err = kii_core_thing_authentication(
            kii,
            EX_AUTH_VENDOR_ID,
            EX_AUTH_VENDOR_PASS);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int create_new_object(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;
    
    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_create_new_object(
            kii,
            &bucket,
            EX_OBJECT_DATA,
            NULL);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int create_new_object_with_id(kii_core_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;
    
    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_create_new_object_with_id(
            kii,
            &bucket,
            id,
            EX_OBJECT_DATA,
            NULL);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int patch_object(kii_core_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_patch_object(
            kii,
            &bucket,
            id,
            EX_OBJECT_DATA,
            NULL);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int replace_object(kii_core_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_replace_object(
            kii,
            &bucket,
            id,
            EX_OBJECT_DATA,
            NULL);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int get_object(kii_core_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_get_object(
            kii,
            &bucket,
            id);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int delete_object(kii_core_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_delete_object(
            kii,
            &bucket,
            id);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int subscribe_bucket(kii_core_t* kii, const char* bucket_name)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_subscribe_bucket(
            kii,
            &bucket);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int unsubscribe_bucket(kii_core_t* kii, const char* bucket_name)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_unsubscribe_bucket(
            kii,
            &bucket);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int create_topic(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    kii_author_t author;

    init_topic(&topic);
    set_author(kii, &author);

    err = kii_core_create_topic(
            kii,
            &topic);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int delete_topic(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    kii_author_t author;

    init_topic(&topic);
    set_author(kii, &author);

    err = kii_core_delete_topic(
            kii,
            &topic);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int subscribe_topic(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    kii_author_t author;

    init_topic(&topic);
    set_author(kii, &author);

    err = kii_core_subscribe_topic(
            kii,
            &topic);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int unsubscribe_topic(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    kii_author_t author;

    init_topic(&topic);
    set_author(kii, &author);

    err = kii_core_unsubscribe_topic(
            kii,
            &topic);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int install_push(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_author_t author;
    set_author(kii, &author);

    err = kii_core_install_thing_push(
            kii,
            KII_FALSE);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int get_endpoint(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_author_t author;
    set_author(kii, &author);

    err = kii_core_get_mqtt_endpoint(
            kii,
            EX_MQTT_ENDPOINT);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

int main(int argc, char** argv)
{
    context_t ctx;
    kii_core_t kii;
    char buff[EX_BUFFER_SIZE];

    int optval;

    /* Initialization */
    init(&kii, buff, &ctx);

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"register", no_argument, NULL,  0},
            {"new-object", no_argument, NULL, 1},
            {"new-object-with-id", no_argument, NULL, 2},
            {"patch-object", no_argument, NULL, 3},
            {"replace-object", no_argument, NULL, 4},
            {"get-object", no_argument, NULL, 5},
            {"delete-object", no_argument, NULL, 6},
            {"subscribe-bucket", no_argument, NULL, 7},
            {"unsubscribe-bucket", no_argument, NULL, 8},
            {"create-topic", no_argument, NULL, 9},
            {"delete-topic", no_argument, NULL, 10},
            {"subscribe-topic", no_argument, NULL, 11},
            {"unsubscribe-topic", no_argument, NULL, 12},
            {"install-push", no_argument, NULL, 13},
            {"get-endpoint", no_argument, NULL, 14},
            {"authentication", no_argument, NULL,  15},
            {"api", no_argument, NULL,  16},
            {"help", no_argument, NULL, 1000},
            {0, 0, 0, 0}
        };

        optval = getopt_long(argc, argv, "",
                 long_options, &option_index);
        if (optval == -1)
            break;

        switch (optval) {
        case 0:
            printf("register thing\n");
            register_thing(&kii);
            break;
        case 1:
            printf("create new object\n");
            create_new_object(&kii);
            break;
        case 2:
            printf("create new object with id\n");
            create_new_object_with_id(&kii, EX_OBJECT_ID);
            break;
        case 3:
            printf("patch object\n");
            patch_object(&kii, EX_OBJECT_ID);
            break;
        case 4:
            printf("replace object\n");
            replace_object(&kii, EX_OBJECT_ID);
            break;
        case 5:
            printf("get object\n");
            get_object(&kii, EX_OBJECT_ID);
            break;
        case 6:
            printf("delete object\n");
            delete_object(&kii, EX_OBJECT_ID);
            break;
        case 7:
            printf("subscribe bucket\n");
            subscribe_bucket(&kii, EX_BUCKET_NAME);
            break;
        case 8:
            printf("unsubscribe bucket\n");
            unsubscribe_bucket(&kii, EX_BUCKET_NAME);
            break;
        case 9:
            printf("create topic\n");
            create_topic(&kii);
            break;
        case 10:
            printf("delete topic\n");
            delete_topic(&kii);
            break;
        case 11:
            printf("subscribe topic\n");
            subscribe_topic(&kii);
            break;
        case 12:
            printf("unsubscribe topic\n");
            unsubscribe_topic(&kii);
            break;
        case 13:
            printf("install push\n");
            install_push(&kii);
            break;
        case 14:
            printf("get endpoint\n");
            get_endpoint(&kii);
            break;
        case 15:
            printf("authentication\n");
            thing_authentication(&kii);
            break;
        case 16:
            printf("api\n");
            kii_core_api_call(&kii, "GET", "hoge/fuga", "body", "text/plain",
                    "x-kii-http-header1:value", "x-kii-http-header2:value2", NULL);
            print_request(&kii);
            break;
        case 1000:
            printf("to configure parameters, edit example.h\n\n");
            printf("commands: \n");
            printf("--register\n register new thing.\n");
            printf("--authentication\n get access token.\n");
            printf("--new-object\n create new object.\n");
            printf("--new-object-with-id\n create new object with id.\n");
            printf("--patch-object\n patch object.\n");
            printf("--replace-object\n replace object.\n");
            printf("--get-object\n get object.\n");
            printf("--delete-object\n delete object.\n");
            printf("--subscribe-bucket\n subscribe bucket.\n");
            printf("--unsubscribe-bucket\n unsubscribe bucket.\n");
            printf("--create-topic\n create topic.\n");
            printf("--delete-topic\n delete topic.\n");
            printf("--subscribe-topic\n subscribe to topic.\n");
            printf("--unsubscribe-topic\n unsubscribe to topic.\n");
            printf("--install-push\n install push.\n");
            printf("--get-endpoint\n get endpoint of MQTT.\n");
            break;
            
        case '?':
            break;
        default:
            printf("?? getopt returned character code 0%o ??\n", optval);
        }
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
    }
    return 0;
}

