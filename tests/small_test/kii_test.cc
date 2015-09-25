#include <stdio.h>
#include <stdarg.h>

// Suppress warnings in gtest.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvariadic-macros"
#pragma GCC diagnostic ignored "-Wlong-long"
#pragma GCC diagnostic ignored "-Wsign-compare"
#include <gtest/gtest.h>
#pragma GCC diagnostic pop

#include <kii_core_init.h>

#define KII_OBJECTID_SIZE 36

#define KII_UPLOADID_SIZE 64

static char APP_HOST[] = "api-development-jp.internal.kii.com";
static char APP_ID[] = "84fff36e";
static char APP_KEY[] = "e45fcc2d31d6aca675af639bc5f04a26";
static char THING_ID[] = "th.53ae324be5a0-26f8-4e11-a13c-03da6fb2";
static char ACCESS_TOKEN[] = "ablTGrnsE20rSRBFKPnJkWyTaeqQ50msqUizvR_61hU";
static char BUCKET[] = "myBucket";
static char TOPIC[] = "myTopic";
static char DUMMY_HEADER[] = "DummyHeader:DummyValue";

static void logger_cb(const char* format, ...)
{
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
}

static void init(
        kii_core_t* kii,
        char* buffer,
        int buffer_size,
        KII_SOCKET_CONNECT_CB connect_cb,
        KII_SOCKET_SEND_CB send_cb,
        KII_SOCKET_RECV_CB recv_cb,
        KII_SOCKET_CLOSE_CB close_cb)
{
    kii_http_context_t* http_ctx;
    memset(kii, 0x00, sizeof(kii_core_t));

    kii_core_init(kii, APP_HOST, APP_ID, APP_KEY);

    http_ctx = &kii->http_context;
    http_ctx->buffer = buffer;
    http_ctx->buffer_size = buffer_size;
    http_ctx->connect_cb = connect_cb;
    http_ctx->send_cb = send_cb;
    http_ctx->recv_cb = recv_cb;
    http_ctx->close_cb = close_cb;
    http_ctx->socket_context.app_context = NULL;

    kii->logger_cb = logger_cb;

    strcpy(kii->author.author_id, THING_ID);
    strcpy(kii->author.access_token, ACCESS_TOKEN);
}

static void initBucket(kii_bucket_t* bucket)
{
    bucket->scope = KII_SCOPE_THING;
    bucket->scope_id = THING_ID;
    bucket->bucket_name = BUCKET;
}

static kii_socket_code_t auth_connect_cb(
        kii_socket_context_t* socket_context,
        const char* host,
        unsigned int port)
{
    EXPECT_NE((kii_socket_context_t*)NULL, socket_context);
    EXPECT_STREQ(APP_HOST, host);
    EXPECT_EQ(443, port);
    return KII_SOCKETC_OK;
}

static int auth_read_counter;

static kii_socket_code_t auth_send_cb(
        kii_socket_context_t* socket_context,
        const char* buffer,
        size_t length)
{
    const char* body = "POST https://api-development-jp.internal.kii.com/api/oauth2/token HTTP/1.1\r\nx-kii-appid:84fff36e\r\nx-kii-appkey:e45fcc2d31d6aca675af639bc5f04a26\r\ncontent-type:application/json\r\ncontent-length:59\r\n\r\n{\"username\":\"VENDOR_THING_ID:1426830900\",\"password\":\"1234\"}";
    int body_length = strlen(body);

    EXPECT_NE((kii_socket_context_t*)NULL, socket_context);

    auth_read_counter = 0;

    EXPECT_STREQ(body, buffer);
    EXPECT_EQ(body_length, length);

    return KII_SOCKETC_OK;
}

static kii_socket_code_t auth_recv_cb(
        kii_socket_context_t* socket_context,
        char* buffer,
        size_t length_to_read,
        size_t* out_actual_length)
{
    const char* body = "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Expose-Headers: Content-Type, Authorization, Content-Length, X-Requested-With, ETag, X-Step-Count\r\nAge: 0\r\nCache-Control: max-age=0, no-cache, no-store\r\nContent-Type: application/json;charset=UTF-8\r\nDate: Fri, 25 Sep 2015 11:07:16 GMT\r\nServer: nginx/1.2.3\r\nVia: 1.1 varnish\r\nX-HTTP-Status-Code: 200\r\nX-Varnish: 726929556\r\nContent-Length: 176\r\nConnection: keep-alive\r\n\r\n{\r\n  \"id\" : \"th.396587a00022-51e9-4e11-5eec-07846c59\",\r\n  \"access_token\" : \"sLvyokzOngTVCRIogpnSV9oSdselet63EoBQiJRu0R4\",\r\n  \"expires_in\" : 2147483639,\r\n  \"token_type\" : \"Bearer\"\r\n}";

    EXPECT_NE((kii_socket_context_t*)NULL, socket_context);
    EXPECT_NE((char*)NULL, buffer);
    EXPECT_TRUE(0 < length_to_read);

    strncpy(buffer, &body[auth_read_counter], length_to_read);
    *out_actual_length = strlen(buffer);
    auth_read_counter += *out_actual_length;

    return KII_SOCKETC_OK;
}

static kii_socket_code_t auth_close_cb(kii_socket_context_t* socket_context)
{
    EXPECT_NE((kii_socket_context_t*)NULL, socket_context);
    return KII_SOCKETC_OK;
}

TEST(kiiTest, authenticate)
{
    kii_error_code_t core_err;
    kii_state_t state;
    char buffer[4096];
    kii_core_t kii;

    init(&kii, buffer, 4096, auth_connect_cb, auth_send_cb, auth_recv_cb,
            auth_close_cb);

    strcpy(kii.author.author_id, "");
    strcpy(kii.author.access_token, "");
    kii.response_code = 0;

    core_err = kii_core_thing_authentication(&kii, "1426830900", "1234");
    ASSERT_EQ(KIIE_OK, core_err);

    do {
        core_err = kii_core_run(&kii);
        state = kii_core_get_state(&kii);
    } while (state != KII_STATE_IDLE);

    ASSERT_EQ(KIIE_OK, core_err);
    ASSERT_EQ(200, kii.response_code);
    ASSERT_STRNE("", kii.response_body);

    ASSERT_TRUE(strstr(kii.response_body, "\"id\"") != NULL);
    ASSERT_TRUE(strstr(kii.response_body, "\"access_token\"") != NULL);
}

