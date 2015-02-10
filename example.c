#include "kii.h"
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
#include <openssl/rand.h>

typedef struct context_t
{
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    int sock;
} context_t;

kii_bool_t my_connect(void* app_context, const char* host)
{
    int sock, ret;
    struct hostent *servhost;
    struct sockaddr_in server;
    struct servent *service;
    context_t* ctx = (context_t*)app_context;
    SSL *ssl;
    SSL_CTX *ssl_ctx;

    printf("host: %s\n", host);
    
    servhost = gethostbyname(host);
    if (servhost == NULL) {
        printf("failed to get host.\n");
        return KII_FALSE;
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
        return KII_FALSE;
    }

    if (connect(sock, (struct sockaddr*) &server, sizeof(server)) == -1 ){
        printf("failed to connect socket.\n");
        return KII_FALSE;
    }

    SSL_library_init();
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL){
        printf("failed to init ssl context.\n");
        return KII_FALSE;
    }

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL){
        printf("failed to init ssl.\n");
        return KII_FALSE;
    }

    ret = SSL_set_fd(ssl, sock);
    if (ret == 0){
        printf("failed to set fd.\n");
        return KII_FALSE;
    }

    RAND_poll();
    while ( RAND_status() == 0 ){
        unsigned short rand_ret = rand() % 65536;
        RAND_seed(&rand_ret, sizeof(rand_ret));
    }

    ret = SSL_connect(ssl);
    if (ret != 1) {
        int sslErr= SSL_get_error(ssl, ret);
        char sslErrStr[120];
        ERR_error_string_n(sslErr, sslErrStr, 120);
        printf("failed to connect: %s\n", sslErrStr);
        return KII_FALSE;
    }
    ctx->sock = sock;
    ctx->ssl = ssl;
    ctx->ssl_ctx = ssl_ctx;
    return KII_TRUE;
}

kii_bool_t my_send(void* app_context, const char* send_buff, int buff_length)
{
    context_t* ctx = (context_t*)app_context;
    int ret = SSL_write(ctx->ssl, send_buff, buff_length);
    if (ret > 0) {
        return KII_TRUE;
    } else {
        printf("failed to send\n");
        return KII_FALSE;
    }
}

kii_bool_t my_recv(void* app_context, char* recv_buff, int length_to_read, int* out_actual_length)
{
    context_t* ctx = (context_t*)app_context;
    int ret = SSL_read(ctx->ssl, recv_buff, length_to_read);
    if (ret > 0) {
        *out_actual_length = ret;
        return KII_TRUE;
    } else {
        printf("failed to receive:\n");
        // TOOD: could be 0 on success?
        *out_actual_length = 0;
        return KII_FALSE;
    }
}


kii_bool_t my_close(void* app_context)
{
    context_t* ctx = (context_t*)app_context;
    int ret = SSL_shutdown(ctx->ssl);
    if (ret != 1) {
        int sslErr= SSL_get_error(ctx->ssl, ret);
        if (sslErr = SSL_ERROR_SYSCALL) {
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
        return KII_FALSE;
    }
    return KII_TRUE;
}

void parse_response(char* buff)
{
    printf("response:\n%s\n", buff);
    /* TODO: implement */
    /* buff : raw http response */
}

int main()
{
    context_t ctx;
    kii_t kii;
    kii_state_t state;
    kii_error_code_t err;
    char buff[4096];
    char thingData[] = "{\"_vendorThingID\":\"thing-xxx-yyy\", \"_password\":\"1234\"}";

    /* Initialization */
    kii.app_id = "9ab34d8b";
    kii.app_key = "7a950d78956ed39f3b0815f0f001b43b";
    kii.app_host = "api-jp.kii.com";
    kii.buffer = buff;
    kii.buffer_size = 4096;
    kii.app_context = &ctx;
    kii.callback_connect_ptr = &my_connect;
    kii.callback_send_ptr = &my_send;
    kii.callback_recv_ptr = &my_recv;
    kii.callback_close_ptr = &my_close;

    /* Register Thing */
    err = kii_register_thing(&kii, thingData);
    printf("request:\n%s\n", kii.buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        state = kii_get_state(&kii);
        err = kii_run(&kii);
        printf ("state : %d\n", state);
        printf ("err: %d\n", err);
        state = kii_get_state(&kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    parse_response(kii.buffer);
}

