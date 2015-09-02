#include "kii_core.h"
#include "kii_libc_wrapper.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>

#ifdef DEBUG
#define M_REQUEST_LINE_CB_FAILED "failed to set request line\n"
#define M_REQUEST_HEADER_CB_FAILED "failed to set request header\n"
#define M_REQUEST_HEADER_CB_AUTH_HEADER "access token is too long\n"
#define M_REQUEST_HEADER_CB_NO_AUTH_HEADER "there is no access token\n"
#define M_REQUEST_APPEND_BODY_START_CB_FAILED "failed to start appending request body\n"
#define M_REQUEST_APPEND_BODY_CB_FAILED "failed to append request body\n"
#define M_REQUEST_APPEND_BODY_END_CB_FAILED "failed to end appending request body\n"

#ifndef __FILE__
#define __FILE__ ("__FILE__ macro is not available")
#endif

#ifndef __LINE__
#define __LINE__ (-1)
#endif

#define M_KII_LOG(x) \
    if (kii->logger_cb != NULL) {\
        kii->logger_cb("file:%s, line:%d ", __FILE__, __LINE__); \
        kii->logger_cb(x); \
    }

#define M_KII_LOG_FORMAT(x) \
    if (kii->logger_cb != NULL) {\
        kii->logger_cb("file:%s, line:%d ", __FILE__, __LINE__); \
        x ; \
    }
#else
#define M_KII_LOG(x)
#define M_KII_LOG_FORMAT(x)
#endif

#if defined(DEBUG) && !defined(USE_CUSTOM_HTTP_CLIENT)
#define M_KII_LOG_DEFAULT_CLIENT(x) M_KII_LOG_FORMAT(x)
#else
#define M_KII_LOG_DEFAULT_CLIENT(x)
#endif

#define M_ACCESS_TOKEN(x, y) \
    x = (kii_strlen((y)) > 0) ? ((y)) : (NULL)

#define M_KII_CONST_STR_LEN(str) (sizeof(str) - 1)
#define M_KII_APPEND_CONSTANT_STR(kii, conststr) \
    prv_kii_http_append_body(kii, conststr, sizeof(conststr) - 1)
#define M_KII_APPEND_STR(kii, str) \
    prv_kii_http_append_body(kii, str, kii_strlen(str))

/*
  This is a size of authorization header.
  128 may be enough size to set authorization header.
  If length of access token becomes large, then this size should be
  changed.
*/
#define MAX_AUTH_BUFF_SIZE 128

#define BEARER "bearer"
#define BEARER_LEN sizeof(BEARER) - 1
#define HTTP1_1 "HTTP/1.1 "
#define END_OF_HEADER "\r\n\r\n"
#define CONST_LEN(str) sizeof(str) - 1

const char DEFAULT_OBJECT_CONTENT_TYPE[] = "application/json";

    kii_error_code_t
kii_core_init(
        kii_core_t* kii,
        const char* site,
        const char* app_id,
        const char* app_key)
{
    M_KII_ASSERT(kii != NULL);
    M_KII_ASSERT(site != NULL);
    M_KII_ASSERT(app_id != NULL);
    M_KII_ASSERT(app_key != NULL);

    memset(kii, 0, sizeof(kii_core_t));
    if(strcmp(site, "CN") == 0)
    {
        kii->app_host = "api-cn2.kii.com";
    }
    else if(strcmp(site, "JP") == 0)
    {
        kii->app_host = "api-jp.kii.com";
    }
    else if(strcmp(site, "US") == 0)
    {
        kii->app_host = "api.kii.com";
    }
    else if(strcmp(site, "SG") == 0)
    {
        kii->app_host = "api-sg.kii.com";
    }
    else
    {
        /* Let's enable to set custom host */
        kii->app_host = (char*)site;
    }

    kii->app_id = (char*)app_id;
    kii->app_key = (char*)app_key;
    return KIIE_OK;
}

    kii_state_t
kii_core_get_state(kii_core_t* kii)
{
    return kii->_state;
}

#ifndef USE_CUSTOM_HTTP_CLIENT

    static kii_http_client_code_t
prv_kii_http_execute(kii_core_t* kii)
{
    kii_http_context_t* http_context = &(kii->http_context);

    M_KII_LOG_FORMAT(kii->logger_cb("socket state: %d\n",
                    http_context->_socket_state));
    switch (http_context->_socket_state) {
        case PRV_KII_SOCKET_STATE_IDLE:
            http_context->_sent_size = 0;
            http_context->_received_size = 0;
            http_context->_socket_state = PRV_KII_SOCKET_STATE_CONNECT;
            return KII_HTTPC_AGAIN;
        case PRV_KII_SOCKET_STATE_CONNECT:
            switch (http_context->connect_cb(&(http_context->socket_context),
                            http_context->host, KII_SERVER_PORT)) {
                case KII_SOCKETC_OK:
                    http_context->_socket_state = PRV_KII_SOCKET_STATE_SEND;
                    return KII_HTTPC_AGAIN;
                case KII_SOCKETC_AGAIN:
                    return KII_HTTPC_AGAIN;
                default:
                    http_context->_socket_state = PRV_KII_SOCKET_STATE_IDLE;
                    return KII_HTTPC_FAIL;
            }
            // This is programing error.
            M_KII_ASSERT(0);
            return KII_HTTPC_FAIL;
        case PRV_KII_SOCKET_STATE_SEND:
        {
            size_t size =
                http_context->total_send_size - http_context->_sent_size;
            if (size > KII_SOCKET_MAX_BUFF_SIZE) {
                size = KII_SOCKET_MAX_BUFF_SIZE;
            }
            switch (http_context->send_cb(&(http_context->socket_context),
                            http_context->buffer + http_context->_sent_size,
                            size)) {
                case KII_SOCKETC_OK:
                    http_context->_sent_size += size;
                    if (http_context->_sent_size ==
                            http_context->total_send_size) {
                        // All contents were sent.
                        http_context->_socket_state = PRV_KII_SOCKET_STATE_RECV;
                    }
                    // If _sent_size is over total_send_size, it is
                    // programming error.
                    M_KII_ASSERT(http_context->_sent_size <=
                            http_context->total_send_size);
                    return KII_HTTPC_AGAIN;
                case KII_SOCKETC_AGAIN:
                    return KII_HTTPC_AGAIN;
                default:
                    http_context->_socket_state = PRV_KII_SOCKET_STATE_IDLE;
                    return KII_HTTPC_FAIL;
            }
            // This is programing error.
            M_KII_ASSERT(0);
            return KII_HTTPC_FAIL;
        }
        case PRV_KII_SOCKET_STATE_RECV:
        {
            size_t actualLength = 0;
            size_t size =
                http_context->buffer_size - http_context->_received_size;
            if (size > KII_SOCKET_MAX_BUFF_SIZE) {
                size = KII_SOCKET_MAX_BUFF_SIZE;
            }
            if (http_context->_received_size == 0) {
                memset(http_context->buffer, 0x00, http_context->buffer_size);
            }

            switch (http_context->recv_cb(&(http_context->socket_context),
                            http_context->buffer + http_context->_received_size,
                            size, &actualLength)) {
                case KII_SOCKETC_OK:
                    http_context->_received_size += actualLength;
                    if (http_context->_received_size >=
                            http_context->buffer_size) {
                        M_KII_LOG("buffer is smaller than receiving data.");
                        return KII_HTTPC_FAIL;
                    }
                    // TODO: We may check content-length and decide to
                    // finish calling recv_cb.
                    if (actualLength < size) {
                        http_context->buffer[http_context->_received_size] =
                            '\0';
                        http_context->_socket_state =
                            PRV_KII_SOCKET_STATE_CLOSE;
                    }
                    return KII_HTTPC_AGAIN;
                case KII_SOCKETC_AGAIN:
                    return KII_HTTPC_AGAIN;
                default:
                    http_context->_socket_state = PRV_KII_SOCKET_STATE_IDLE;
                    return KII_HTTPC_FAIL;
            }
            // This is programing error.
            M_KII_ASSERT(0);
            return KII_HTTPC_FAIL;
        }
        case PRV_KII_SOCKET_STATE_CLOSE:
        {
            switch (http_context->close_cb(&(http_context->socket_context))) {
                case KII_HTTPC_OK:
                {
                    /* parse status code */
                    char* pointer = strstr(http_context->buffer, HTTP1_1);
                    int i = 0;
                    if (pointer == NULL) {
                        M_KII_LOG("invalid response.");
                        return KII_HTTPC_FAIL;
                    }

                    kii->response_code = 0;
                    pointer += CONST_LEN(HTTP1_1);
                    // parse status code.
                    for (i = 0; i < 3; ++i) {
                        if (isdigit(pointer[i]) == 0) {
                            M_KII_LOG("invalid status code.");
                            kii->response_code = 0;
                            return KII_HTTPC_FAIL;
                        }
                        kii->response_code = (kii->response_code * 10) +
                                (pointer[i] - '0');
                    }

                    /* set body pointer */
                    kii->response_body =
                        strstr(http_context->buffer, END_OF_HEADER);
                    if (kii->response_body != NULL) {
                        kii->response_body += CONST_LEN(END_OF_HEADER);
                    }
                    http_context->_socket_state = PRV_KII_SOCKET_STATE_IDLE;
                    return KII_HTTPC_OK;
                }
                case KII_HTTPC_AGAIN:
                    return KII_HTTPC_AGAIN;
                default:
                    http_context->_socket_state = PRV_KII_SOCKET_STATE_IDLE;
                    return KII_HTTPC_FAIL;
            }
            // This is programing error.
            M_KII_ASSERT(0);
            return KII_HTTPC_FAIL;
        }
    }

    // This is programing error.
    M_KII_ASSERT(0);
    return KII_HTTPC_FAIL;
}

    static kii_http_client_code_t
prv_kii_http_set_request_line(
        kii_core_t* kii,
        const char* method,
        const char* resource_path)
{
    kii_http_context_t* http_context = &(kii->http_context);
    http_context->host = kii->app_host;

    memset(http_context->buffer, 0x00, http_context->buffer_size);

    if (http_context->buffer_size <=
            (kii_strlen(method) + kii_strlen(kii->app_host) +
                    kii_strlen(resource_path) + 21)) {
        M_KII_LOG("buffer size too short. can't insert request line.\n");
        return KII_HTTPC_FAIL;
    }

    http_context->total_send_size =
        sprintf(http_context->buffer,
                "%s https://%s/%s HTTP/1.1\r\n", method, kii->app_host,
                resource_path);

    http_context->_body_position =
        http_context->buffer + http_context->total_send_size;

    // Correct position of initializing socket_state is under consideration.
    http_context->_socket_state = PRV_KII_SOCKET_STATE_IDLE;
    return KII_HTTPC_OK;
}

    static kii_http_client_code_t
prv_kii_http_set_header(
        kii_core_t* kii,
        const char* key,
        const char* value)
{
    kii_http_context_t* http_context = &(kii->http_context);
    char* insert_positin = http_context->_body_position;
    size_t header_size = 0;
    size_t body_size = http_context->total_send_size -
            (http_context->_body_position - http_context->buffer);
    size_t len;
    header_size = strlen(key);
    header_size += strlen(":");
    header_size += strlen(value);
    header_size += strlen("\r\n");

    if (http_context->buffer_size <=
            header_size + http_context->total_send_size) {
        M_KII_LOG("buffer size too short. can't insert header.\n");
        return KII_HTTPC_FAIL;
    }
    // move body.
    memmove(http_context->_body_position + header_size,
            http_context->_body_position, body_size);
    http_context->_body_position += header_size;
    http_context->buffer[http_context->total_send_size + header_size] = '\0';

    // set header.
    len = kii_strlen(key);
    memcpy(insert_positin, key, len);
    insert_positin += len;

    len = kii_strlen(":");
    memcpy(insert_positin, ":", len);
    insert_positin += len;

    len = kii_strlen(value);
    memcpy(insert_positin, value, len);
    insert_positin += len;

    len = kii_strlen("\r\n");
    memcpy(insert_positin, "\r\n", len);

    http_context->total_send_size += header_size;
    return KII_HTTPC_OK;
}

    static kii_http_client_code_t
prv_kii_http_append_body(
        kii_core_t* kii,
        const char* body,
        size_t body_len)
{
    kii_http_context_t* http_context = &(kii->http_context);

    if (http_context->buffer_size <=
            http_context->total_send_size + body_len) {
        M_KII_LOG("buffer size too short. can't insert body.\n");
        return KII_HTTPC_FAIL;
    }

    if (body == NULL) {
        return KII_HTTPC_FAIL;
    }

    strncat(http_context->buffer, body, body_len);
    http_context->total_send_size = kii_strlen(http_context->buffer);
    return KII_HTTPC_OK;
}

static kii_http_client_code_t prv_kii_http_append_body_start(kii_core_t* kii)
{
    return prv_kii_http_append_body(kii, "\r\n", 2);
}

static kii_http_client_code_t prv_kii_http_append_body_end(kii_core_t* kii)
{
    // Nothing to do.
    return KII_HTTPC_OK;
}

#else

    static kii_http_client_code_t
prv_kii_http_execute(kii_core_t* kii)
{
    return kii->http_execute_cb(&(kii->http_context), &(kii->response_code),
            &(kii->response_body));
}

    static kii_http_client_code_t
prv_kii_http_set_request_line(
        kii_core_t* kii,
        const char* method,
        const char* resource_path)
{
    return kii->http_set_request_line_cb(&(kii->http_context),
            method, kii->app_host, resource_path);
}

    static kii_http_client_code_t
prv_kii_http_set_header(
        kii_core_t* kii,
        const char* key,
        const char* value)
{
    return kii->http_set_header_cb(&(kii->http_context), key, value);
}

    static kii_http_client_code_t
prv_kii_http_append_body(
        kii_core_t* kii,
        const char* body,
        size_t body_len)
{
    return kii->http_append_body_cb(&(kii->http_context), body, body_len);
}

static kii_http_client_code_t prv_kii_http_append_body_start(kii_core_t* kii)
{
    return kii->http_append_body_start_cb(&(kii->http_context));
}

static kii_http_client_code_t prv_kii_http_append_body_end(kii_core_t* kii)
{
    return kii->http_append_body_end_cb(&(kii->http_context));
}

#endif

    kii_error_code_t
kii_core_run(kii_core_t* kii)
{
    kii_http_client_code_t cbr;
    switch(kii->_state) {
        case KII_STATE_IDLE:
            return KIIE_FAIL;
        case KII_STATE_READY:
            M_KII_LOG_DEFAULT_CLIENT(kii->logger_cb(
                    "request: %s\n", kii->http_context.buffer));
            kii->_state = KII_STATE_EXECUTE;
            return KIIE_OK;
        case KII_STATE_EXECUTE:
            cbr = prv_kii_http_execute(kii);
            if (cbr == KII_HTTPC_OK) {
                M_KII_LOG_DEFAULT_CLIENT(kii->logger_cb(
                        "response core: %d, response body: %s\n",
                        kii->response_code, kii->response_body));
                kii->_state = KII_STATE_IDLE;
                return KIIE_OK;
            } else if (cbr == KII_HTTPC_AGAIN) {
                return KIIE_OK;
            } else {
                M_KII_LOG_DEFAULT_CLIENT(
                        kii->logger_cb("fail to send request\n"));
                kii->_state = KII_STATE_IDLE;
                return KIIE_FAIL;
            }
        default:
            M_KII_ASSERT(0);

    }
}

    static void
prv_content_length_str(
        size_t content_length,
        char* buff,
        size_t buff_len)
{
    kii_sprintf(buff, "%lu", ((unsigned long)content_length));
}

    static void
prv_set_thing_register_path(kii_core_t* kii)
{
    kii_sprintf(kii->_http_request_path,
            "api/apps/%s/things",
            kii->app_id);
}

    static kii_error_code_t 
prv_http_request_line_and_headers(
        kii_core_t* kii,
        const char* method,
        const char* resource_path,
        const char* content_type,
        const char* access_token,
        const char* etag)
{
    kii_http_client_code_t result;
    result = prv_kii_http_set_request_line(kii, method, resource_path);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
        return KIIE_FAIL;
    }

    result = prv_kii_http_set_header(
            kii,
            "x-kii-appid",
            kii->app_id);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }

    result = prv_kii_http_set_header(
            kii,
            "x-kii-appkey",
            kii->app_key);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }

    if (content_type != NULL) {
        result = prv_kii_http_set_header(
                kii,
                "content-type",
                content_type
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            return KIIE_FAIL;
        }
    }

    if (access_token != NULL) {
        char bearer[] = "bearer ";
        char bearer_buff[MAX_AUTH_BUFF_SIZE];

        if (kii_strlen(access_token) + kii_strlen(bearer) >= MAX_AUTH_BUFF_SIZE) {
            M_KII_LOG(M_REQUEST_HEADER_CB_AUTH_HEADER);
            return KIIE_FAIL;
        }
        kii_memset(bearer_buff, 0x00, MAX_AUTH_BUFF_SIZE);
        kii_sprintf(bearer_buff, "%s%s", bearer, access_token);
        result = prv_kii_http_set_header(
                kii,
                "authorization",
                bearer_buff
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            return KIIE_FAIL;
        }
    }

    if (etag != NULL) {
        result = prv_kii_http_set_header(
                kii,
                "if-match",
                etag 
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            return KIIE_FAIL;
        }
    }
    return KIIE_OK;
}

    static kii_error_code_t
prv_http_request(
        kii_core_t* kii,
        const char* method,
        const char* resource_path,
        const char* content_type,
        const char* access_token,
        const char* etag,
        const char* body)
{
    kii_http_client_code_t result = KII_HTTPC_FAIL;
    kii_error_code_t retval = prv_http_request_line_and_headers(kii, method,
            resource_path, content_type, access_token, etag);

    if (retval != KIIE_OK) {
        return retval;
    }

    if (body != NULL) {
        size_t body_len;
        char content_length[8];
        body_len = kii_strlen(body);
        kii_memset(content_length, 0x00, 8);
        prv_content_length_str(body_len, content_length, 8);
        result = prv_kii_http_set_header(
                kii,
                "content-length",
                content_length
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            return KIIE_FAIL;
        }

        result = prv_kii_http_append_body_start(kii);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_APPEND_BODY_START_CB_FAILED);
            return KIIE_FAIL;
        }

        result = prv_kii_http_append_body(
                kii,
                body, body_len);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
            return KIIE_FAIL;
        }

        result = prv_kii_http_append_body_end(kii);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_APPEND_BODY_END_CB_FAILED);
            return KIIE_FAIL;
        }
    } else {
        result = prv_kii_http_append_body_start(kii);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_APPEND_BODY_START_CB_FAILED);
            return KIIE_FAIL;
        }

        result = prv_kii_http_append_body_end(kii);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_APPEND_BODY_END_CB_FAILED);
            return KIIE_FAIL;
        }
    }
    return KIIE_OK;
}

    static void
prv_bucket_path(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        char* path)
{
    switch(bucket->scope) {
        case KII_SCOPE_APP:
            kii_sprintf(path,
                    "api/apps/%s/buckets/%s",
                    kii->app_id,
                    bucket->bucket_name);
            break;
        case KII_SCOPE_USER:
            kii_sprintf(path,
                    "api/apps/%s/users/%s/buckets/%s",
                    kii->app_id,
                    bucket->scope_id,
                    bucket->bucket_name);
            break;
        case KII_SCOPE_GROUP:
            kii_sprintf(path,
                    "api/apps/%s/groups/%s/buckets/%s",
                    kii->app_id,
                    bucket->scope_id,
                    bucket->bucket_name);
            break;
        case KII_SCOPE_THING:
            kii_sprintf(path,
                    "api/apps/%s/things/%s/buckets/%s",
                    kii->app_id,
                    bucket->scope_id,
                    bucket->bucket_name);
            break;
    }
}

    static void
prv_topic_path(
        kii_core_t* kii,
        const kii_topic_t* topic,
        char* path)
{
    switch(topic->scope) {
        case KII_SCOPE_APP:
            kii_sprintf(path,
                    "api/apps/%s/topic/%s",
                    kii->app_id,
                    topic->topic_name);
            break;
        case KII_SCOPE_USER:
            kii_sprintf(path,
                    "api/apps/%s/users/%s/topic/%s",
                    kii->app_id,
                    topic->scope_id,
                    topic->topic_name);
            break;
        case KII_SCOPE_GROUP:
            kii_sprintf(path,
                    "api/apps/%s/groups/%s/topics/%s",
                    kii->app_id,
                    topic->scope_id,
                    topic->topic_name);
            break;
        case KII_SCOPE_THING:
            kii_sprintf(path,
                    "api/apps/%s/things/%s/topics/%s",
                    kii->app_id,
                    topic->scope_id,
                    topic->topic_name);
            break;
    }
}

    kii_error_code_t
kii_core_register_thing(
        kii_core_t* kii,
        const char* thing_data)
{
    kii_error_code_t result;
    prv_set_thing_register_path(kii);
    result = prv_http_request(
            kii,
            "POST",
            kii->_http_request_path,
            "application/vnd.kii.ThingRegistrationAndAuthorizationRequest+json",
            NULL,
            NULL,
            thing_data
            );

    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_register_thing_with_id(
        kii_core_t* kii,
        const char* vendor_thing_id,
        const char* password,
        const char* thing_type)
{
    kii_error_code_t result;
    char content_length_str[8];
    size_t content_length = 0;

    prv_set_thing_register_path(kii);
    result = prv_http_request_line_and_headers(
            kii,
            "POST",
            kii->_http_request_path,
            "application/vnd.kii.ThingRegistrationAndAuthorizationRequest+json",
            NULL,
            NULL
            );

    content_length = M_KII_CONST_STR_LEN("{\"_vendorThingID\":\"");
    content_length += kii_strlen(vendor_thing_id);
    content_length += M_KII_CONST_STR_LEN("\",\"_password\":\"");
    content_length += kii_strlen(password);
    content_length += M_KII_CONST_STR_LEN("\",\"_thingType\":\"");
    content_length += kii_strlen(thing_type);
    content_length += M_KII_CONST_STR_LEN("\"}");
    kii_memset(content_length_str, 0x00, 8);
    prv_content_length_str(content_length, content_length_str, 8);
    if (prv_kii_http_set_header(kii,
                     "content-length", content_length_str) != KII_HTTPC_OK) {
        return KIIE_FAIL;
    }

    if (prv_kii_http_append_body_start(kii) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_START_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_CONSTANT_STR(kii, "{\"_vendorThingID\":\"") !=
            KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_STR(kii, vendor_thing_id) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_CONSTANT_STR(kii, "\",\"_password\":\"") != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_STR(kii, password) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_CONSTANT_STR(kii, "\",\"_thingType\":\"") !=
            KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_STR(kii, thing_type) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_CONSTANT_STR(kii, "\"}") != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (prv_kii_http_append_body_end(kii) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_END_CB_FAILED);
        return KIIE_FAIL;
    }

    kii->_state = KII_STATE_READY;
    return KIIE_OK;
}

    static void
prv_set_auth_path(kii_core_t* kii)
{
    kii_sprintf(kii->_http_request_path,
            "api/oauth2/token");
}

    kii_error_code_t
kii_core_thing_authentication(kii_core_t* kii,
        const char* vendor_thing_id,
        const char* password
        )
{
    kii_error_code_t result;
    char content_length_str[8];
    size_t content_length = 0;

    prv_set_auth_path(kii);

    result = prv_http_request_line_and_headers(
            kii,
            "POST",
            kii->_http_request_path,
            "application/json",
            NULL,
            NULL
            );
    if (result != KIIE_OK) {
        return result;
    }

    content_length = M_KII_CONST_STR_LEN("{\"username\":\"VENDOR_THING_ID:");
    content_length += kii_strlen(vendor_thing_id);
    content_length += M_KII_CONST_STR_LEN("\",\"password\":\"");
    content_length += kii_strlen(password);
    content_length += M_KII_CONST_STR_LEN("\"}");

    kii_memset(content_length_str, 0x00, 8);
    prv_content_length_str(content_length, content_length_str, 8);
    if (prv_kii_http_set_header(kii,
                    "content-length", content_length_str) != KII_HTTPC_OK) {
        return KIIE_FAIL;
    }

    if (prv_kii_http_append_body_start(kii) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_START_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_CONSTANT_STR(kii, "{\"username\":\"VENDOR_THING_ID:") !=
            KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_STR(kii, vendor_thing_id) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_CONSTANT_STR(kii, "\",\"password\":\"") != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_STR(kii, password) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_CONSTANT_STR(kii, "\"}") != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (prv_kii_http_append_body_end(kii) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_END_CB_FAILED);
        return KIIE_FAIL;
    }

    kii->_state = KII_STATE_READY;
    return KIIE_OK;
}


    kii_error_code_t
kii_core_create_new_object(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_data,
        const char* object_content_type)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_bucket_path(kii, bucket, kii->_http_request_path);
    kii_strcat(kii->_http_request_path, "/objects");
    if (object_content_type == NULL) {
        object_content_type = DEFAULT_OBJECT_CONTENT_TYPE;
    }
    result = prv_http_request(
            kii,
            "POST",
            kii->_http_request_path,
            object_content_type,
            access_token,
            NULL,
            object_data);

    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_create_new_object_with_id(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* object_data,
        const char* object_content_type
        )
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_bucket_path(kii, bucket, kii->_http_request_path);
    kii_sprintf(kii->_http_request_path,
            "%s/objects/%s",
            kii->_http_request_path,
            object_id);
    if (object_content_type == NULL) {
        object_content_type = DEFAULT_OBJECT_CONTENT_TYPE;
    }
    result = prv_http_request(
            kii,
            "PUT",
            kii->_http_request_path,
            object_content_type,
            access_token,
            NULL,
            object_data);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_patch_object(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* patch_data,
        const char* opt_etag)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_bucket_path(kii, bucket, kii->_http_request_path);
    kii_sprintf(kii->_http_request_path,
            "%s/objects/%s",
            kii->_http_request_path,
            object_id);
    result = prv_http_request(
            kii,
            "PATCH",
            kii->_http_request_path,
            NULL,
            access_token,
            opt_etag,
            patch_data);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_replace_object(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* replace_data,
        const char* opt_etag)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_bucket_path(kii, bucket, kii->_http_request_path);
    kii_sprintf(kii->_http_request_path,
            "%s/objects/%s",
            kii->_http_request_path,
            object_id);
    result = prv_http_request(
            kii,
            "PUT",
            kii->_http_request_path,
            NULL,
            access_token,
            opt_etag,
            replace_data);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_get_object(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_bucket_path(kii, bucket, kii->_http_request_path);
    kii_sprintf(kii->_http_request_path,
            "%s/objects/%s",
            kii->_http_request_path,
            object_id);
    result = prv_http_request(
            kii,
            "GET",
            kii->_http_request_path,
            NULL,
            access_token,
            NULL,
            NULL);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_delete_object(
        kii_core_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_bucket_path(kii, bucket, kii->_http_request_path);
    kii_sprintf(kii->_http_request_path,
            "%s/objects/%s",
            kii->_http_request_path,
            object_id);
    result = prv_http_request(
            kii,
            "DELETE",
            kii->_http_request_path,
            NULL,
            access_token,
            NULL,
            NULL);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_subscribe_bucket(
        kii_core_t* kii,
        const kii_bucket_t* bucket)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_bucket_path(kii, bucket, kii->_http_request_path);
    kii_sprintf(kii->_http_request_path,
            "%s/filters/all/push/subscriptions/things",
            kii->_http_request_path);
    result = prv_http_request(
            kii,
            "POST",
            kii->_http_request_path,
            NULL,
            access_token,
            NULL,
            NULL);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_unsubscribe_bucket(
        kii_core_t* kii,
        const kii_bucket_t* bucket)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_bucket_path(kii, bucket, kii->_http_request_path);
    kii_sprintf(kii->_http_request_path,
            "%s/filters/all/push/subscriptions/things/%s",
            kii->_http_request_path,
            kii->author.author_id);
    result = prv_http_request(
            kii,
            "DELETE",
            kii->_http_request_path,
            NULL,
            access_token,
            NULL,
            NULL);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_create_topic(
        kii_core_t* kii,
        const kii_topic_t* topic)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_topic_path(kii, topic, kii->_http_request_path);
    result = prv_http_request(
            kii,
            "PUT",
            kii->_http_request_path,
            NULL,
            access_token,
            NULL,
            NULL);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_delete_topic(
        kii_core_t* kii,
        const kii_topic_t* topic)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_topic_path(kii, topic, kii->_http_request_path);
    result = prv_http_request(
            kii,
            "DELETE",
            kii->_http_request_path,
            NULL,
            access_token,
            NULL,
            NULL);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_subscribe_topic(
        kii_core_t* kii,
        const kii_topic_t* topic)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_topic_path(kii, topic, kii->_http_request_path);
    kii_sprintf(kii->_http_request_path,
            "%s/push/subscriptions/things",
            kii->_http_request_path);
    result = prv_http_request(
            kii,
            "POST",
            kii->_http_request_path,
            NULL,
            access_token,
            NULL,
            NULL);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_unsubscribe_topic(
        kii_core_t* kii,
        const kii_topic_t* topic)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_topic_path(kii, topic, kii->_http_request_path);
    kii_sprintf(kii->_http_request_path,
            "%s/push/subscriptions/things/%s",
            kii->_http_request_path,
            kii->author.author_id);
    result = prv_http_request(
            kii,
            "DELETE",
            kii->_http_request_path,
            NULL,
            access_token,
            NULL,
            NULL);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    static void
prv_set_installation_path(kii_core_t* kii)
{
    kii_sprintf(kii->_http_request_path,
            "api/apps/%s/installations",
            kii->app_id);
}

    static void
prv_set_mqtt_endpoint_path(kii_core_t* kii, const char* installation_id)
{
    kii_sprintf(kii->_http_request_path,
            "api/apps/%s/installations/%s/mqtt-endpoint",
            kii->app_id,
            installation_id);
}
    kii_error_code_t
kii_core_install_thing_push(
        kii_core_t* kii,
        kii_bool_t development)
{
    kii_error_code_t result;
    size_t content_length = 0;
    char content_length_str[8];
    char* access_token;
    char* c_development;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    c_development = ((development == KII_TRUE) ? ("true") : ("false"));
    prv_set_installation_path(kii);

    result = prv_http_request_line_and_headers(
            kii,
            "POST",
            kii->_http_request_path,
            "application/vnd.kii.InstallationCreationRequest+json",
            access_token,
            NULL);
    if (result != KIIE_OK) {
        return result;
    }

    content_length = M_KII_CONST_STR_LEN(
            "{\"installationType\":\"MQTT\",\"development\":");
    content_length += kii_strlen(c_development);
    content_length += M_KII_CONST_STR_LEN("}");
    kii_memset(content_length_str, 0x00, 8);
    prv_content_length_str(content_length, content_length_str, 8);
    if (prv_kii_http_set_header(kii,
                    "content-length", content_length_str) != KII_HTTPC_OK) {
        return KIIE_FAIL;
    }
    if (prv_kii_http_append_body_start(kii) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_START_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_CONSTANT_STR(kii,
                    "{\"installationType\":\"MQTT\",\"development\":") !=
            KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_STR(kii, c_development) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (M_KII_APPEND_CONSTANT_STR(kii, "}") != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    if (prv_kii_http_append_body_end(kii) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_END_CB_FAILED);
        return KIIE_FAIL;
    }

    kii->_state = KII_STATE_READY;
    return KIIE_OK;
}

    kii_error_code_t
kii_core_get_mqtt_endpoint(
        kii_core_t* kii,
        const char* installation_id)
{
    kii_error_code_t result;
    char* access_token;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    prv_set_mqtt_endpoint_path(kii, installation_id);
    result = prv_http_request(
            kii,
            "GET",
            kii->_http_request_path,
            NULL,
            access_token,
            NULL,
            NULL);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_core_api_call(
        kii_core_t* kii,
        const char* http_method,
        const char* resource_path,
        const char* http_body,
        size_t body_size,
        const char* content_type,
        char* header,
        ...)
{
    va_list ap;
    char *str;
    char key[128];
    char value[128];
    char *ptr;
    char *access_token = NULL;
    kii_error_code_t ret = KIIE_FAIL;
    kii_http_client_code_t result;

    va_start(ap, header);
    memset(key, 0x00, sizeof(key));
    memset(value, 0x00, sizeof(value));

    result = prv_kii_http_set_request_line(kii, http_method, resource_path);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
        return KIIE_FAIL;
    }

    /* set app id */
    result = prv_kii_http_set_header(
            kii,
            "x-kii-appid",
            kii->app_id);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        goto exit;
    }

    /* set app key */
    result = prv_kii_http_set_header(
            kii,
            "x-kii-appkey",
            kii->app_key);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        goto exit;
    }

    /* set content-type */
    if (content_type != NULL) {
        result = prv_kii_http_set_header(
                kii,
                "content-type",
                content_type
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            goto exit;
        }
    }
    
    /* set access token if there are. */
    M_ACCESS_TOKEN(access_token, kii->author.access_token);
    memset(value, 0x00, sizeof(value));
    kii_sprintf(value, "%s%s", "bearer ", access_token);
    if (access_token != NULL) {
        result = prv_kii_http_set_header(
                kii,
                "authorization",
                value);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
            goto exit;
        }
    }

    /* set additional header */
    if (header != NULL) {
        str = header;
        ptr = strstr(str, ":");
        if (ptr == NULL) {
            goto exit;
        }
        strncpy(key, str, ptr - str);
        strncpy(value, ptr + 1, sizeof(value));
        M_KII_LOG_FORMAT(kii->logger_cb("key: %s\n", key));
        M_KII_LOG_FORMAT(kii->logger_cb("value: %s\n", value));
        result = prv_kii_http_set_header(
                kii,
                key,
                value);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
            goto exit;
        }
        /* set additional headers */
        while(1) {
            str = va_arg(ap, char*);
            if (str == NULL)
                break;
            ptr = strstr(str, ":");
            if (ptr == NULL) {
               break;
            }
            strncpy(key, str, ptr - str);
            strncpy(value, ptr + 1, sizeof(value));
            M_KII_LOG_FORMAT(kii->logger_cb("key: %s\n", key));
            M_KII_LOG_FORMAT(kii->logger_cb("value: %s\n", value));
            result = prv_kii_http_set_header(
                    kii,
                    key,
                    value);
            if (result != KII_HTTPC_OK) {
                M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
                goto exit;
            }
        }
    }

    /* set body */
    if (http_body != NULL) {
        char content_length[8];
        kii_memset(content_length, 0x00, 8);
        prv_content_length_str(body_size, content_length, 8);
        result = prv_kii_http_set_header(
                kii,
                "content-length",
                content_length
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            goto exit;
        }
        result = prv_kii_http_append_body_start(kii);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_APPEND_BODY_START_CB_FAILED);
            goto exit;
        }

        result = prv_kii_http_append_body(kii, http_body,
                body_size);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
            goto exit;
        }

        result = prv_kii_http_append_body_end(kii);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_APPEND_BODY_END_CB_FAILED);
            goto exit;
        }
    } else {
        result = prv_kii_http_append_body_start(kii);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_APPEND_BODY_START_CB_FAILED);
            goto exit;
        }

        result = prv_kii_http_append_body_end(kii);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_APPEND_BODY_END_CB_FAILED);
            goto exit;
        }
    }
    kii->_state = KII_STATE_READY;
    ret = KIIE_OK;
exit:
    va_end(ap);
    return ret;
}

static kii_http_client_code_t
prv_kii_core_set_authorization_header(kii_core_t* kii)
{
    if (kii_strlen(kii->author.access_token) <= 0) {
        M_KII_LOG(M_REQUEST_HEADER_CB_NO_AUTH_HEADER);
        return KII_HTTPC_FAIL;
    } else if (BEARER_LEN + kii_strlen(kii->author.access_token) + 1 >=
            MAX_AUTH_BUFF_SIZE) {
        M_KII_LOG(M_REQUEST_HEADER_CB_AUTH_HEADER);
        return KII_HTTPC_FAIL;
    } else {
        char access_token[MAX_AUTH_BUFF_SIZE];
        memset(access_token, 0x00, sizeof(access_token));
        kii_sprintf(access_token, "%s %s", BEARER, kii->author.access_token);
        return prv_kii_http_set_header(kii, "authorization", access_token);
    }
}

kii_error_code_t
kii_core_api_call_start(
        kii_core_t* kii,
        const char* http_method,
        const char* resource_path,
        const char* content_type,
        kii_bool_t set_authentication_header)
{
    // set request line.
    if (prv_kii_http_set_request_line(kii, http_method,
                    resource_path) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
        return KIIE_FAIL;
    }

    // set default headers.
    if (prv_kii_http_set_header(kii, "x-kii-appid",
                    kii->app_id) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }
    if (prv_kii_http_set_header(kii, "x-kii-appkey",
                    kii->app_key) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }
    if (prv_kii_http_set_header(kii, "content-type",
                    content_type) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }
    if (set_authentication_header == KII_TRUE) {
        if (prv_kii_core_set_authorization_header(kii) != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
            return KIIE_FAIL;
        }
    }

    // start body cb.
    if (prv_kii_http_append_body_start(kii) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_START_CB_FAILED);
        return KIIE_FAIL;
    }
    kii->_content_length = 0;

    return KIIE_OK;

}

static kii_http_client_code_t
prv_kii_core_http_set_content_length_header(
        kii_core_t* kii,
        size_t content_length)
{
    if (content_length > 0) {
        char content_length_str[8];
        kii_memset(content_length_str, 0x00, 8);
        prv_content_length_str(content_length, content_length_str, 8);
        return prv_kii_http_set_header(kii, "content-length",
                content_length_str);
    } else {
        return KII_HTTPC_FAIL;
    }
}

kii_error_code_t kii_core_api_call_end(kii_core_t* kii)
{
    // close body cb.
    if (prv_kii_http_append_body_end(kii) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_END_CB_FAILED);
        return KIIE_FAIL;
    }

    // set content length.
    if (prv_kii_core_http_set_content_length_header(kii,
                    kii->_content_length) != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }

    // set reday.
    if (kii->_state != KII_STATE_IDLE) {
        return KIIE_FAIL;
    }
    kii->_state = KII_STATE_READY;
    return KIIE_OK;
}

kii_error_code_t
kii_core_api_call_append_body(
        kii_core_t* kii,
        const char* body_data,
        size_t body_size)
{
    if (prv_kii_http_append_body(kii, body_data, body_size) !=
            KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_APPEND_BODY_CB_FAILED);
        return KIIE_FAIL;
    }
    kii->_content_length += body_size;
    return KIIE_OK;
}

kii_error_code_t
kii_core_api_call_append_header(
        kii_core_t* kii,
        const char* key,
        const char* value)
{
    if (prv_kii_http_set_header(kii,key, value) != KIIE_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }
    return KIIE_OK;
}

/* vim:set ts=4 sts=4 sw=4 et fenc=UTF-8 ff=unix: */
