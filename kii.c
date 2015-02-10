#include "kii.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

kii_state_t
kii_get_state(kii_t* kii)
{
    return kii->_state;
}

kii_error_code_t
kii_run(kii_t* kii)
{
    kii_bool_t callbackResult;
    switch(kii->_state) {
        case KII_STATE_IDLE:
            return KIIE_FAIL;
        case KII_STATE_READY:
            kii->_sent_size = 0;
            kii->_last_chunk = 0;
            kii->_received_size = 0;
            kii->_state = KII_STATE_CONNECT;
            return KIIE_OK;
        case KII_STATE_CONNECT:
            callbackResult = kii->callback_connect_ptr(kii->app_context, kii->app_host);
            if (callbackResult == KII_TRUE) {
                kii->_state = KII_STATE_SEND;
                return KIIE_OK;
            } else {
                kii->_state = KII_STATE_IDLE;
                return KIIE_FAIL;
            }
        case KII_STATE_SEND:
            {
                int remain;
                int size = BUFF_SIZE;
                remain = strlen(kii->buffer) - kii->_sent_size;
                if (remain < BUFF_SIZE) {
                    size = remain;
                    kii->_last_chunk = 1;
                }
                callbackResult =
                    kii->callback_send_ptr(
                            kii->app_context,
                            kii->buffer + kii->_sent_size,
                            size);
                if (callbackResult == KII_TRUE) {
                    kii->_sent_size += size;
                    if (kii->_last_chunk > 0) {
                        kii->_state = KII_STATE_RECV;
                    }
                    return KIIE_OK;
                } else {
                    kii->_state = KII_STATE_IDLE;
                    return KIIE_FAIL;
                }
            }
        case KII_STATE_RECV:
            {
                int actualLength = 0;
                char* buffPtr = kii->buffer + kii->_received_size;
                if (kii->_received_size == 0) {
                    memset(kii->buffer, 0x00, kii->buffer_size);
                }
                callbackResult = kii->callback_recv_ptr(
                        kii->app_context,
                        buffPtr, BUFF_SIZE,
                        &actualLength);
                if (callbackResult == KII_TRUE) {
                    printf("recv buff:\n%s\n", kii->buffer);
                    kii->_received_size += actualLength;
                    if (actualLength < BUFF_SIZE) {
                        kii->_state = KII_STATE_CLOSE;
                    }
                    return KIIE_OK;
                } else {
                    kii->_state = KII_STATE_IDLE;
                    return KIIE_FAIL;
                }
            }
        case KII_STATE_CLOSE:
            callbackResult = kii->callback_close_ptr(kii->app_context);
            kii->_state = KII_STATE_IDLE;
            if (callbackResult == KII_TRUE) {
                return KIIE_OK;
            }
            return KIIE_FAIL;
        default:
            assert(0);
    }
}

static void prv_print_request_line(kii_t* kii, char* method)
{
    sprintf(kii->buffer, "%s %s HTTP/1.1\r\n", method, kii->request_url);
}

static void prv_print_kii_headers(kii_t* kii)
{
    strcat(kii->buffer, "x-kii-appid:");
    strcat(kii->buffer, kii->app_id);
    strcat(kii->buffer, "\r\n");
    strcat(kii->buffer, "x-kii-appkey:");
    strcat(kii->buffer, kii->app_key);
    strcat(kii->buffer, "\r\n");
}

static size_t prv_calculate_content_length(const char* request_body)
{
    return strlen(request_body);
}

static void prv_print_content_length(kii_t* kii, size_t length)
{
    assert(length <= 99999999);
    char slength[8];
    sprintf(slength, "%zu", length);
    strcat(kii->buffer, "content-length:");
    strcat(kii->buffer, slength);
    strcat(kii->buffer, "\r\n");
}

static void prv_print_content_type(kii_t* kii, char* content_type)
{
    strcat(kii->buffer, "content-type:");
    strcat(kii->buffer, content_type);
    strcat(kii->buffer, "\r\n");
}

static void prv_print_CRLF(kii_t* kii)
{
    strcat(kii->buffer, "\r\n");
}

static void prv_print_body(kii_t* kii, const char* request_body)
{
    strcat(kii->buffer, request_body);
}

static void prv_set_thing_register_url(kii_t* kii)
{
    sprintf(kii->request_url,
            "https://%s/api/apps/%s/things",
            kii->app_host,
            kii->app_id);
}

kii_error_code_t
kii_register_thing(kii_t* kii,
        const char* thing_data)
{
    prv_set_thing_register_url(kii);
    prv_print_request_line(kii, "POST");
    prv_print_kii_headers(kii);
    prv_print_content_type(kii,
            "application/vnd.kii.ThingRegistrationAndAuthorizationRequest+json");
    size_t contentLength = prv_calculate_content_length(thing_data);
    prv_print_content_length(kii, contentLength);
    prv_print_CRLF(kii);
    prv_print_body(kii, thing_data);
    kii->_state = KII_STATE_READY;

    return KIIE_OK;
}

kii_error_code_t
kii_create_new_object(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_data)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_create_new_object_with_id(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_id,
        const char* object_data)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_patch_object(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_id,
        const char* patch_data,
        const char* opt_etag)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_replace_object(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_id,
        const char* replace_data,
        const char* opt_etag)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_get_object(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_id)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_delete_object(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_id)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_subscribe_bucket(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_unsubscribe_bucket(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_subscribe_topic(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* topic_name)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_unsubscribe_topic(kii_t* app,
        const char* access_token,
        const char* thing_id,
        const char* topic_name)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_install_thing_push(kii_t* kii,
        const char* access_token,
        kii_bool_t development)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_get_mqtt_endpoint(kii_t* kii,
        const char* access_token,
        const char** installation_id)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

