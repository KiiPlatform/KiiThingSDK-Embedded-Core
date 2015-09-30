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

#define DEF_APP_HOST "api-development-jp.internal.kii.com"
#define DEF_APP_ID "84fff36e"
#define DEF_APP_KEY "e45fcc2d31d6aca675af639bc5f04a26"
#define DEF_THING_ID "th.53ae324be5a0-26f8-4e11-a13c-03da6fb2"
#define DEF_ACCESS_TOKEN "ablTGrnsE20rSRBFKPnJkWyTaeqQ50msqUizvR_61hU"
#define DEF_BUCKET "myBucket"
#define DEF_OBJECT "myObject"

static char APP_HOST[] = DEF_APP_HOST;
static char APP_ID[] = DEF_APP_ID;
static char APP_KEY[] = DEF_APP_KEY;
static char THING_ID[] = DEF_THING_ID;
static char ACCESS_TOKEN[] = DEF_ACCESS_TOKEN;
static char BUCKET[] = DEF_BUCKET;
static char OBJECT[] = DEF_OBJECT;
static char TOPIC[] = "myTopic";
static char DUMMY_HEADER[] = "DummyHeader:DummyValue";

static int send_counter;
static int recv_counter;

typedef struct _test_context
{
    const char *send_body;
    const char *recv_body;
} test_context_t;

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
        test_context_t* test_ctx,
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
    http_ctx->socket_context.app_context = test_ctx;

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

static kii_socket_code_t common_connect_cb(
        kii_socket_context_t* socket_context,
        const char* host,
        unsigned int port)
{
    EXPECT_NE((kii_socket_context_t*)NULL, socket_context);
    EXPECT_STREQ(APP_HOST, host);
    EXPECT_EQ(443, port);

    send_counter = 0;
    recv_counter = 0;

    return KII_SOCKETC_OK;
}

static kii_socket_code_t common_send_cb(
        kii_socket_context_t* socket_context,
        const char* buffer,
        size_t length)
{
    test_context_t* ctx = (test_context_t*)socket_context->app_context;

    EXPECT_NE((char*)NULL, buffer);
    EXPECT_TRUE(0 < length);

    EXPECT_STREQ(&(ctx->send_body[send_counter]), buffer);
    send_counter += length;

    return KII_SOCKETC_OK;
}

static kii_socket_code_t common_recv_cb(
        kii_socket_context_t* socket_context,
        char* buffer,
        size_t length_to_read,
        size_t* out_actual_length)
{
    test_context_t* ctx = (test_context_t*)socket_context->app_context;

    EXPECT_NE((char*)NULL, buffer);
    EXPECT_TRUE(0 < length_to_read);

    strncpy(buffer, &(ctx->recv_body[recv_counter]), length_to_read);
    *out_actual_length = strlen(buffer);
    recv_counter += *out_actual_length;

    return KII_SOCKETC_OK;
}

static kii_socket_code_t common_close_cb(kii_socket_context_t* socket_context)
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
    const char* send_body =
"POST https://" DEF_APP_HOST "/api/oauth2/token HTTP/1.1\r\n"
"x-kii-appid:" DEF_APP_ID "\r\n"
"x-kii-appkey:" DEF_APP_KEY "\r\n"
"content-type:application/json\r\n"
"content-length:59\r\n"
"\r\n"
"{\"username\":\"VENDOR_THING_ID:1426830900\",\"password\":\"1234\"}";
    const char* recv_body =
"HTTP/1.1 200 OK\r\n"
"Accept-Ranges: bytes\r\n"
"Access-Control-Allow-Origin: *\r\n"
"Access-Control-Expose-Headers: Content-Type, Authorization, Content-Length, X-Requested-With, ETag, X-Step-Count\r\n"
"Age: 0\r\n"
"Cache-Control: max-age=0, no-cache, no-store\r\n"
"Content-Type: application/json;charset=UTF-8\r\n"
"Date: Fri, 25 Sep 2015 11:07:16 GMT\r\n"
"Server: nginx/1.2.3\r\n"
"Via: 1.1 varnish\r\n"
"X-HTTP-Status-Code: 200\r\n"
"X-Varnish: 726929556\r\n"
"Content-Length: 176\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"{\n"
"  \"id\" : \"" DEF_THING_ID "\",\n"
"  \"access_token\" : \"" DEF_ACCESS_TOKEN "\",\n"
"  \"expires_in\" : 2147483639,\n"
"  \"token_type\" : \"Bearer\"\n"
"}";
    test_context_t ctx;

    ctx.send_body = send_body;
    ctx.recv_body = recv_body;

    init(&kii, buffer, 4096, &ctx, common_connect_cb, common_send_cb,
            common_recv_cb, common_close_cb);

    strcpy(kii.author.author_id, "");
    strcpy(kii.author.access_token, "");
    kii.response_code = 0;
    kii.response_body = NULL;

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

TEST(kiiTest, register)
{
    kii_error_code_t core_err;
    kii_state_t state;
    char buffer[4096];
    const char* thingData = "{\"_vendorThingID\":\"4792\",\"_password\":\"1234\",\"_thingType\":\"my_type\"}";
    kii_core_t kii;
    const char* send_body =
"POST https://" DEF_APP_HOST "/api/apps/" DEF_APP_ID "/things HTTP/1.1\r\n"
"x-kii-appid:" DEF_APP_ID "\r\n"
"x-kii-appkey:" DEF_APP_KEY "\r\n"
"content-type:application/vnd.kii.ThingRegistrationAndAuthorizationRequest+json\r\n"
"content-length:67\r\n"
"\r\n"
"{\"_vendorThingID\":\"4792\",\"_password\":\"1234\",\"_thingType\":\"my_type\"}";
    const char* recv_body =
"HTTP/1.1 201 Created\r\n"
"Accept-Ranges: bytes\r\n"
"Access-Control-Allow-Origin: *\r\n"
"Access-Control-Expose-Headers: Content-Type, Authorization, Content-Length, X-Requested-With, ETag, X-Step-Count\r\n"
"Age: 0\r\n"
"Cache-Control: max-age=0, no-cache, no-store\r\n"
"Content-Type: application/vnd.kii.ThingRegistrationAndAuthorizationResponse+json;charset=UTF-8\r\n"
"Date: Tue, 29 Sep 2015 05:42:52 GMT\r\n"
"Location: https://" DEF_APP_HOST "/api/apps/" DEF_APP_ID "/things/" DEF_THING_ID "\r\n"
"Server: nginx/1.2.3\r\n"
"Via: 1.1 varnish\r\n"
"X-HTTP-Status-Code: 201\r\n"
"X-Varnish: 1950832960\r\n"
"Content-Length: 208\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"{\n"
"  \"_thingID\" : \"" DEF_THING_ID "\",\n"
"  \"_vendorThingID\" : \"4972\",\n"
"  \"_created\" : 1443505372909,\n"
"  \"_disabled\" : false,\n"
"  \"_accessToken\" : \"" DEF_ACCESS_TOKEN "\"\n"
"}";
    test_context_t ctx;

    ctx.send_body = send_body;
    ctx.recv_body = recv_body;

    init(&kii, buffer, 4096, &ctx, common_connect_cb, common_send_cb,
            common_recv_cb, common_close_cb);

    strcpy(kii.author.author_id, "");
    strcpy(kii.author.access_token, "");
    kii.response_code = 0;
    kii.response_body = NULL;

    core_err = kii_core_register_thing(&kii, thingData);
    ASSERT_EQ(KIIE_OK, core_err);

    do {
        core_err = kii_core_run(&kii);
        state = kii_core_get_state(&kii);
    } while (state != KII_STATE_IDLE);

    ASSERT_EQ(KIIE_OK, core_err);
    ASSERT_EQ(201, kii.response_code);
    ASSERT_TRUE(kii.response_body != NULL);
    ASSERT_STRNE("", kii.response_body);

    ASSERT_TRUE(strstr(kii.response_body, "\"_accessToken\"") != NULL);
    ASSERT_TRUE(strstr(kii.response_body, "\"_thingID\"") != NULL);
}

TEST(kiiTest, register_with_id)
{
    kii_error_code_t core_err;
    kii_state_t state;
    char buffer[4096];
    kii_core_t kii;
    const char* send_body =
"POST https://" DEF_APP_HOST "/api/apps/" DEF_APP_ID "/things HTTP/1.1\r\n"
"x-kii-appid:" DEF_APP_ID "\r\n"
"x-kii-appkey:" DEF_APP_KEY "\r\n"
"content-type:application/vnd.kii.ThingRegistrationAndAuthorizationRequest+json\r\n"
"content-length:67\r\n"
"\r\n"
"{\"_vendorThingID\":\"4792\",\"_password\":\"1234\",\"_thingType\":\"my_type\"}";
    const char* recv_body =
"HTTP/1.1 201 Created\r\n"
"Accept-Ranges: bytes\r\n"
"Access-Control-Allow-Origin: *\r\n"
"Access-Control-Expose-Headers: Content-Type, Authorization, Content-Length, X-Requested-With, ETag, X-Step-Count\r\n"
"Age: 0\r\n"
"Cache-Control: max-age=0, no-cache, no-store\r\n"
"Content-Type: application/vnd.kii.ThingRegistrationAndAuthorizationResponse+json;charset=UTF-8\r\n"
"Date: Tue, 29 Sep 2015 05:42:52 GMT\r\n"
"Location: https://" DEF_APP_HOST "/api/apps/" DEF_APP_ID "/things/" DEF_THING_ID "\r\n"
"Server: nginx/1.2.3\r\n"
"Via: 1.1 varnish\r\n"
"X-HTTP-Status-Code: 201\r\n"
"X-Varnish: 1950832960\r\n"
"Content-Length: 208\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"{\n"
"  \"_thingID\" : \"" DEF_THING_ID "\",\n"
"  \"_vendorThingID\" : \"4972\",\n"
"  \"_created\" : 1443505372909,\n"
"  \"_disabled\" : false,\n"
"  \"_accessToken\" : \"" DEF_ACCESS_TOKEN "\"\n"
"}";
    test_context_t ctx;

    ctx.send_body = send_body;
    ctx.recv_body = recv_body;

    init(&kii, buffer, 4096, &ctx, common_connect_cb, common_send_cb,
            common_recv_cb, common_close_cb);

    strcpy(kii.author.author_id, "");
    strcpy(kii.author.access_token, "");
    kii.response_code = 0;
    kii.response_body = NULL;

    core_err = kii_core_register_thing_with_id(&kii, "4792", "1234",
            "my_type");
    ASSERT_EQ(KIIE_OK, core_err);

    do {
        core_err = kii_core_run(&kii);
        state = kii_core_get_state(&kii);
    } while (state != KII_STATE_IDLE);

    ASSERT_EQ(KIIE_OK, core_err);
    ASSERT_EQ(201, kii.response_code);
    ASSERT_TRUE(kii.response_body != NULL);
    ASSERT_STRNE("", kii.response_body);

    ASSERT_TRUE(strstr(kii.response_body, "\"_accessToken\"") != NULL);
    ASSERT_TRUE(strstr(kii.response_body, "\"_thingID\"") != NULL);
}

TEST(kiiTest, create_new_object)
{
    kii_error_code_t core_err;
    kii_state_t state;
    char buffer[4096];
    kii_core_t kii;
    kii_bucket_t bucket;
    const char* send_body =
"POST https://" DEF_APP_HOST "/api/apps/" DEF_APP_ID "/things/" DEF_THING_ID "/buckets/" DEF_BUCKET "/objects HTTP/1.1\r\n"
"x-kii-appid:" DEF_APP_ID "\r\n"
"x-kii-appkey:" DEF_APP_KEY "\r\n"
"content-type:application/json\r\n"
"authorization:bearer " DEF_ACCESS_TOKEN "\r\n"
"content-length:2\r\n"
"\r\n"
"{}";
    const char* recv_body =
"HTTP/1.1 201 Created\r\n"
"Accept-Ranges: bytes\r\n"
"Access-Control-Allow-Origin: *\r\n"
"Access-Control-Expose-Headers: Content-Type, Authorization, Content-Length, X-Requested-With, ETag, X-Step-Count\r\n"
"Age: 0\r\n"
"Cache-Control: max-age=0, no-cache, no-store\r\n"
"Content-Type: application/vnd.kii.ObjectCreationResponse+json;charset=UTF-8\r\n"
"Date: Wed, 30 Sep 2015 06:18:20 GMT\r\n"
"ETag: \"1\"\r\n"
"Location: https://" DEF_APP_HOST "/api/apps/" DEF_APP_ID "/things/" DEF_THING_ID "/buckets/rw:" DEF_BUCKET "/objects/10e9d740-673b-11e5-ac56-123143070e33\r\n"
"Server: nginx/1.2.3\r\n"
"Via: 1.1 varnish\r\n"
"X-HTTP-Status-Code: 201\r\n"
"X-Varnish: 734543441\r\n"
"Content-Length: 123\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"{\n"
"  \"objectID\" : \"10e9d740-673b-11e5-ac56-123143070e33\",\n"
"  \"createdAt\" : 1443593908916,\n"
"  \"dataType\" : \"application/json\"\n"
"}";
    test_context_t ctx;

    ctx.send_body = send_body;
    ctx.recv_body = recv_body;

    init(&kii, buffer, 4096, &ctx, common_connect_cb, common_send_cb,
            common_recv_cb, common_close_cb);

    initBucket(&bucket);

    kii.response_code = 0;
    kii.response_body = NULL;

    core_err = kii_core_create_new_object(&kii, &bucket, "{}", NULL);
    ASSERT_EQ(KIIE_OK, core_err);

    do {
        core_err = kii_core_run(&kii);
        state = kii_core_get_state(&kii);
    } while (state != KII_STATE_IDLE);

    ASSERT_EQ(KIIE_OK, core_err);
    ASSERT_EQ(201, kii.response_code);
    ASSERT_STREQ(THING_ID, kii.author.author_id);
    ASSERT_STREQ(ACCESS_TOKEN, kii.author.access_token);
 
    ASSERT_TRUE(kii.response_body != NULL);
    ASSERT_STREQ(
            "{\n  \"objectID\" : \"10e9d740-673b-11e5-ac56-123143070e33\",\n  \"createdAt\" : 1443593908916,\n  \"dataType\" : \"application/json\"\n}",
            kii.response_body);
}

TEST(kiiTest, create_new_object_with_id)
{
    kii_error_code_t core_err;
    kii_state_t state;
    char buffer[4096];
    kii_core_t kii;
    kii_bucket_t bucket;
    const char* send_body =
"PUT https://" DEF_APP_HOST "/api/apps/" DEF_APP_ID "/things/" DEF_THING_ID "/buckets/" DEF_BUCKET "/objects/" DEF_OBJECT " HTTP/1.1\r\n"
"x-kii-appid:" DEF_APP_ID "\r\n"
"x-kii-appkey:" DEF_APP_KEY "\r\n"
"content-type:application/json\r\n"
"authorization:bearer " DEF_ACCESS_TOKEN "\r\n"
"content-length:2\r\n"
"\r\n"
"{}";
    const char* recv_body =
"HTTP/1.1 201 Created\r\n"
"Accept-Ranges: bytes\r\n"
"Access-Control-Allow-Origin: *\r\n"
"Access-Control-Expose-Headers: Content-Type, Authorization, Content-Length, X-Requested-With, ETag, X-Step-Count\r\n"
"Age: 0\r\n"
"Cache-Control: max-age=0, no-cache, no-store\r\n"
"Content-Type: application/vnd.kii.ObjectUpdateResponse+json;charset=UTF-8\r\n"
"Date: Wed, 30 Sep 2015 06:51:15 GMT\r\n"
"ETag: \"1\"\r\n"
"Location: https://" DEF_APP_HOST "/api/apps/" DEF_APP_ID "/things/" DEF_THING_ID "/buckets/rw:" DEF_BUCKET "/objects/" DEF_OBJECT "\r\n"
"Server: nginx/1.2.3\r\n"
"Via: 1.1 varnish\r\n"
"X-HTTP-Status-Code: 201\r\n"
"X-Varnish: 734584055\r\n"
"Content-Length: 65\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"{\n"
"  \"createdAt\" : 1443595884290,\n"
"  \"modifiedAt\" : 1443595884290\n"
"}";
    test_context_t ctx;

    ctx.send_body = send_body;
    ctx.recv_body = recv_body;

    init(&kii, buffer, 4096, &ctx, common_connect_cb, common_send_cb,
            common_recv_cb, common_close_cb);

    initBucket(&bucket);

    kii.response_code = 0;
    kii.response_body = NULL;

    core_err = kii_core_create_new_object_with_id(&kii, &bucket, OBJECT,
            "{}", NULL);
    ASSERT_EQ(KIIE_OK, core_err);

    do {
        core_err = kii_core_run(&kii);
        state = kii_core_get_state(&kii);
    } while (state != KII_STATE_IDLE);

    ASSERT_EQ(KIIE_OK, core_err);
    ASSERT_EQ(201, kii.response_code);
    ASSERT_STREQ(THING_ID, kii.author.author_id);
    ASSERT_STREQ(ACCESS_TOKEN, kii.author.access_token);
 
    ASSERT_TRUE(kii.response_body != NULL);
    ASSERT_STREQ(
            "{\n  \"createdAt\" : 1443595884290,\n  \"modifiedAt\" : 1443595884290\n}",
            kii.response_body);
}

