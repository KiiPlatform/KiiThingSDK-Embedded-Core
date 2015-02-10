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

kii_bool_t my_connect(void* app_context, const char* host, const char* path)
{
    int sock, ret;
    struct hostent *servhost;
    struct sockaddr_in server;
    struct servent *service;
    context_t* ctx = (context_t*)app_context;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    
    servhost = gethostbyname(host);
    if (servhost == NULL) {
        printf("failed to get host.\n)";
        return KII_FALSE;
    }
    memset(&server, sizeof(server), 0x00);
    server.sin_family = AF_INET;
    /* More secure. */
    memcpy(servhost->h_addr, &(server.sin_addr), servhost->h_length);

    /* Get Port number */
    service = getservbyname("https", "tcp");
    if (service != NULL) {
        server.sin_port = service->s_port;
    } else {
        server.sin_port = htons(443);
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("failed to init socket.\n)";
        return KII_FALSE;
    }

    SSL_load_error_strings();
    SSL_library_init();
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL){
        printf("failed to init ssl context.\n)";
        return KII_FALSE;
    }

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL){
        printf("failed to init ssl.\n)";
        return KII_FALSE;
    }

    ret = SSL_set_fd(ssl, sock);
    if (ret == 0){
        printf("failed to set fd.\n)";
        return KII_FALSE;
    }

    RAND_poll();
    while ( RAND_status() == 0 ){
        unsigned short rand_ret = rand() % 65536;
        RAND_seed(&rand_ret, sizeof(rand_ret));
    }

    ret = SSL_connect(ssl);
    if ( ret != 1 ){
        printf("failed to connect.\n)";
        return KII_FALSE;
    }
    ctx->sock = sock;
    ctx->ssl = ssl;
    ctx->ssl_ctx = ssl_ctx;
    return KII_TRUE;
}

kii_bool_t my_send(void* app_context, const char* send_buff, int buff_length)
{
    /* TODO: implement. */
    return KII_TRUE;
}

kii_bool_t my_recv(void* app_context, char* recv_buff, int length_to_read, int* out_actual_length)
{
    /* TODO: implement. */
    return KII_TRUE;
}


kii_bool_t my_close(void* app_context)
{
    /* TODO: implement. */
    return KII_TRUE;
}

void parse_response(char* buff)
{
    /* TODO: implement */
    /* buff : raw http response */
}

int main()
{
    kii_t kii;
    kii_state_t state;
    kii_error_code_t err;
    char buff[4096];
    char thingData[] = "{\"_vendorThindID\":\"thing-xxx-yyy\", \"_password\":\"1234\"}";

    /* Initialization */
    kii.app_id = "my-app-id";
    kii.app_key = "my-app-key";
    kii.app_host = "api-jp.kii.com";
    kii.buffer = buff;
    kii.callback_connect_ptr = &my_connect;
    kii.callback_send_ptr = &my_send;
    kii.callback_recv_ptr = &my_recv;
    kii.callback_close_ptr = &my_close;

    /* Register Thing */
    err = kii_register_thing(&kii, thingData);
    printf("request:\n%s\n", kii.buffer);
    if (err != KIIE_OK) {
        return 1;
    }
    while (1) {
        err = kii_run(&kii);
        state = kii_get_state(&kii);
        if (state == KII_STATE_IDLE) {
            /* End of operation. */
            break;
        }
    }
    if (err != KIIE_OK) {
        return 1;
    }
    parse_response(kii.buffer);
}

