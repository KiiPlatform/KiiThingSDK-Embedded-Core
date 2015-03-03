#include "kii.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>


#ifdef DEBUG
#define M_REQUEST_LINE_CB_FAILED "failed to set request line\n"
#define M_REQUEST_HEADER_CB_FAILED "failed to set request header\n"
#define M_REQUEST_BODY_CB_FAILED "failed to set request body\n"

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
#else
#define M_KII_LOG(x)
#endif

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

    static void
prv_content_length_str(
        size_t content_length,
        char* buff,
        size_t buff_len)
{
    snprintf(buff, buff_len, "%zu", content_length);
}

    static void
prv_set_thing_register_path(kii_t* kii)
{
    sprintf(kii->_http_request_path,
            "api/apps/%s/things",
            kii->app_id);
}

    static kii_http_client_code_t
prv_http_request(
        kii_t* kii,
        const char* method,
        const char* resource_path,
        const char* content_type,
        const char* access_token,
        const char* body)
{
    kii_http_client_code_t result;
    result = kii->http_set_request_line_cb(
            kii->http_context,
            method,
            kii->app_host,
            resource_path);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
        return KIIE_FAIL;
    }

    result = kii->http_set_header_cb(
            kii->http_context,
            "x-kii-appid",
            kii->app_id);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }

    result = kii->http_set_header_cb(
            kii->http_context,
            "x-kii-appkey",
            kii->app_key);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }

    if (content_type != NULL) {
        result = kii->http_set_header_cb(
                kii->http_context,
                "content-type",
                content_type
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            return KIIE_FAIL;
        }
    }

    if (access_token != NULL) {
        char bearer = "bearer ";
        int token_len = strlen(access_token);
        int bearer_len = token_len + strlen(bearer);
        char* bearer_buff[bearer_len + 1];
        memset(bearer_buff, 0x00, bearer_len + 1);
        sprintf(bearer_buff, "%s %s", bearer, access_token);
        result = kii->http_set_header_cb(
                kii->http_context,
                "authorization",
                bearer_buff
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            return KIIE_FAIL;
        }
    }

    if (body != NULL) {
        char content_length[8];
        memset(content_length, 0x00, 8);
        prv_content_length_str(strlen(body), content_length, 8);
        result = kii->http_set_header_cb(
                kii->http_context,
                "content-length",
                content_length
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            return KIIE_FAIL;
        }

        kii->http_set_body_cb(
                kii->http_context,
                body);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_BODY_CB_FAILED);
            return KIIE_FAIL;
        }
    }
    return KIIE_OK;
}


    kii_error_code_t
kii_register_thing(
        kii_t* kii,
        const char* thing_data)
{
    kii_http_client_code_t result;
    prv_set_thing_register_path(kii);
    result = prv_http_request(
            kii,
            "POST",
            kii->_http_request_path,
            "application/vnd.kii.ThingRegistrationAndAuthorizationRequest+json",
            NULL,
            thing_data
            );

    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_create_new_object(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_data)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_create_new_object_with_id(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* object_data)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_patch_object(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* patch_data,
        const char* opt_etag)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_replace_object(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* replace_data,
        const char* opt_etag)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_get_object(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_id)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_delete_object(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_id)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_subscribe_bucket(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_unsubscribe_bucket(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_subscribe_topic(
        kii_t* kii,
        const char* access_token,
        const kii_topic_t* topic)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_unsubscribe_topic(
        kii_t* app,
        const char* access_token,
        const kii_topic_t* topic)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_install_thing_push(
        kii_t* kii,
        const char* access_token,
        kii_bool_t development)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

    kii_error_code_t
kii_get_mqtt_endpoint(
        kii_t* kii,
        const char* access_token,
        const char** installation_id)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

