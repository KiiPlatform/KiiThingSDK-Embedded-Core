#include "kii.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

kii_state_t
kii_get_state(kii_t* kii)
{
    /* TODO: implement. */
    return KII_STATE_IDLE;
}

kii_error_code_t
kii_run(kii_t* kii)
{
    int ret = KIIE_FAIL;
    switch(kii->_state) {
        case KII_STATE_IDLE:
            kii->_sent_size = 0;
            kii->_last_chunk = 0;
            kii->_received_size = 0;
            break;
        case KII_STATE_CONNECT:
            break;
        case KII_STATE_SEND:
            break;
        case KII_STATE_RECV:
            break;
        case KII_STATE_CLOSE:
            break;
    }
    /* TODO: implement. */
    return KIIE_FAIL;
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

