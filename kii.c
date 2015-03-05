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

const char DEFAULT_OBJECT_CONTENT_TYPE[] = "application/json";

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
        const char* etag,
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
        char bearer[] = "bearer ";
        int token_len = strlen(access_token);
        int bearer_len = token_len + strlen(bearer);
        char* bearer_buff[bearer_len + 1];
        memset(bearer_buff, 0x00, bearer_len + 1);
        sprintf(bearer_buff, "%s%s", bearer, access_token);
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

    if (etag != NULL) {
        result = kii->http_set_header_cb(
                kii->http_context,
                "etag",
                etag 
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
    } else {
        kii->http_set_body_cb(
                kii->http_context,
                NULL);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_BODY_CB_FAILED);
            return KIIE_FAIL;
        }
    }
    return KIIE_OK;
}

    static void
prv_bucket_path(
        kii_t* kii,
        const kii_bucket_t* bucket,
        char* path)
{
    switch(bucket->scope) {
        case KII_SCOPE_APP:
            sprintf(path,
                    "api/apps/%s/buckets/%s",
                    kii->app_id,
                    bucket->bucket_name);
            break;
        case KII_SCOPE_USER:
            sprintf(path,
                    "api/apps/%s/users/%s/buckets/%s",
                    kii->app_id,
                    bucket->scope_id,
                    bucket->bucket_name);
            break;
        case KII_SCOPE_GROUP:
            sprintf(path,
                    "api/apps/%s/groups/%s/buckets/%s",
                    kii->app_id,
                    bucket->scope_id,
                    bucket->bucket_name);
            break;
        case KII_SCOPE_THING:
            sprintf(path,
                    "api/apps/%s/things/%s/buckets/%s",
                    kii->app_id,
                    bucket->scope_id,
                    bucket->bucket_name);
            break;
    }
}

    static void
prv_topic_path(
        kii_t* kii,
        const kii_topic_t* topic,
        char* path)
{
    switch(topic->scope) {
        case KII_SCOPE_APP:
            sprintf(path,
                    "api/apps/%s/topic/%s",
                    kii->app_id,
                    topic->topic_name);
            break;
        case KII_SCOPE_USER:
            sprintf(path,
                    "api/apps/%s/users/%s/topic/%s",
                    kii->app_id,
                    topic->scope_id,
                    topic->topic_name);
            break;
        case KII_SCOPE_GROUP:
            sprintf(path,
                    "api/apps/%s/groups/%s/topics/%s",
                    kii->app_id,
                    topic->scope_id,
                    topic->topic_name);
            break;
        case KII_SCOPE_THING:
            sprintf(path,
                    "api/apps/%s/things/%s/topics/%s",
                    kii->app_id,
                    topic->scope_id,
                    topic->topic_name);
            break;
    }
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
        const kii_bucket_t* bucket,
        const char* object_data,
        const char* object_content_type)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);

    prv_bucket_path(kii, bucket, kii->_http_request_path);
    strcat(kii->_http_request_path, "/objects");
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
kii_create_new_object_with_id(
        kii_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* object_data,
        const char* object_content_type
        )
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
    prv_bucket_path(kii, bucket, kii->_http_request_path);
    sprintf(kii->_http_request_path,
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
kii_patch_object(
        kii_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* patch_data,
        const char* opt_etag)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
    prv_bucket_path(kii, bucket, kii->_http_request_path);
    sprintf(kii->_http_request_path,
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
kii_replace_object(
        kii_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* replace_data,
        const char* opt_etag)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
    prv_bucket_path(kii, bucket, kii->_http_request_path);
    sprintf(kii->_http_request_path,
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
kii_get_object(
        kii_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
    prv_bucket_path(kii, bucket, kii->_http_request_path);
    sprintf(kii->_http_request_path,
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
kii_delete_object(
        kii_t* kii,
        const kii_bucket_t* bucket,
        const char* object_id)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
    prv_bucket_path(kii, bucket, kii->_http_request_path);
    sprintf(kii->_http_request_path,
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
kii_subscribe_bucket(
        kii_t* kii,
        const kii_bucket_t* bucket)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
    prv_bucket_path(kii, bucket, kii->_http_request_path);
    sprintf(kii->_http_request_path,
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
kii_unsubscribe_bucket(
        kii_t* kii,
        const kii_bucket_t* bucket)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
    prv_bucket_path(kii, bucket, kii->_http_request_path);
    sprintf(kii->_http_request_path,
            "%s/filters/all/push/subscriptions/things/%s",
            kii->_http_request_path,
            kii->author->author_id);
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
kii_create_topic(
        kii_t* kii,
        const kii_topic_t* topic)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
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
kii_delete_topic(
        kii_t* kii,
        const kii_topic_t* topic)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
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
kii_subscribe_topic(
        kii_t* kii,
        const kii_topic_t* topic)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
    prv_topic_path(kii, topic, kii->_http_request_path);
    sprintf(kii->_http_request_path,
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
kii_unsubscribe_topic(
        kii_t* kii,
        const kii_topic_t* topic)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
    prv_topic_path(kii, topic, kii->_http_request_path);
    sprintf(kii->_http_request_path,
            "%s/push/subscriptions/things/%s",
            kii->_http_request_path,
            kii->author->author_id);
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
prv_set_installation_path(kii_t* kii)
{
    sprintf(kii->_http_request_path,
            "api/apps/%s/installations",
            kii->app_id);
}

    static void
prv_set_mqtt_endpoint_path(kii_t* kii, const char* installation_id)
{
    sprintf(kii->_http_request_path,
            "api/apps/%s/installations/%s/mqtt-endpoint",
            kii->app_id,
            installation_id);
}
    kii_error_code_t
kii_install_thing_push(
        kii_t* kii,
        kii_bool_t development)
{
    kii_http_client_code_t result;
    char body[256];
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
    char* c_development = development == KII_TRUE ? "true" : "false";
    prv_set_installation_path(kii);

    memset(body, 0x00, 256);
    sprintf(body,
            "{\"installationType\":\"MQTT\", \"development\":%s}",
            c_development);
    result = prv_http_request(
            kii,
            "POST",
            kii->_http_request_path,
            "application/vnd.kii.InstallationCreationRequest+json",
            access_token,
            NULL,
            body);
    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
}

    kii_error_code_t
kii_get_mqtt_endpoint(
        kii_t* kii,
        const char* installation_id)
{
    kii_http_client_code_t result;
    char* access_token = (kii->author != NULL) ?
        (kii->author->access_token) : (NULL);
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

