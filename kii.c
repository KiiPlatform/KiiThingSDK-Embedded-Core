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
    kii_http_client_code_t cbr;
    switch(kii->_state) {
        case KII_STATE_IDLE:
            return KIIE_FAIL;
        case KII_STATE_READY:
            kii->_state = KII_STATE_EXECUTE;
            return KIIE_OK;
        case KII_STATE_EXECUTE:
            cbr = kii->http_execute_cb(
                    kii->http_context,
                    &(kii->response_code),
                    &(kii->response_body));
            if (cbr == KII_HTTPC_OK) {
                kii->_state = KII_STATE_IDLE;
                return KIIE_OK;
            } else if (cbr == KII_HTTPC_AGAIN) {
                return KIIE_OK;
            } else {
                kii->_state = KII_STATE_IDLE;
                return KIIE_FAIL;
            }
        default:
            assert(0);
    }
}

static void prv_content_length_str(size_t content_length, char* buff, size_t buff_len)
{
    snprintf(buff, buff_len, "%zu", content_length);
}

static void prv_set_thing_register_path(kii_t* kii)
{
    sprintf(kii->_http_request_path,
            "api/apps/%s/things",
            kii->app_id);
}

kii_error_code_t
kii_register_thing(kii_t* kii,
        const char* thing_data)
{
    prv_set_thing_register_path(kii);
    kii->http_set_request_line_cb(
            kii->http_context,
            "POST",
            kii->app_host,
            kii->_http_request_path);
    kii->http_set_header_cb(
            kii->http_context,
            "content-type",
            "application/vnd.kii.ThingRegistrationAndAuthorizationRequest+json");
    kii->http_set_header_cb(
            kii->http_context,
            "x-kii-appid",
            kii->app_id);
    kii->http_set_header_cb(
            kii->http_context,
            "x-kii-appkey",
            kii->app_key);
    char content_length[8];
    memset(content_length, 0x00, 8);
    prv_content_length_str(strlen(thing_data), content_length, 8);
    kii->http_set_header_cb(
            kii->http_context,
            "content-length",
            content_length);
    kii->http_set_body_cb(
            kii->http_context,
            thing_data);

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

