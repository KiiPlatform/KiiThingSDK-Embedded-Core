#include "kii_core.h"
#include "kii_libc_wrapper.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef DEBUG
#define M_REQUEST_LINE_CB_FAILED "failed to set request line\n"
#define M_REQUEST_HEADER_CB_FAILED "failed to set request header\n"
#define M_REQUEST_HEADER_CB_AUTH_HEADER "access token is too long\n"
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

#define M_KII_LOG_FORMAT(x) \
    if (kii->logger_cb != NULL) {\
        kii->logger_cb("file:%s, line:%d ", __FILE__, __LINE__); \
        x ; \
    }
#else
#define M_KII_LOG(x)
#define M_KII_LOG_FORMAT(x)
#endif

#define M_ACCESS_TOKEN(x, y) \
    x = (kii_strlen((y)) > 0) ? ((y)) : (NULL)

/*
  This is a size of authorization header.
  128 may be enough size to set authorization header.
  If length of access token becomes large, then this size should be
  changed.
*/
#define MAX_AUTH_BUFF_SIZE 128

const char DEFAULT_OBJECT_CONTENT_TYPE[] = "application/json";

    kii_state_t
kii_core_get_state(kii_core_t* kii)
{
    return kii->_state;
}

    kii_error_code_t
kii_core_run(kii_core_t* kii)
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
                    &(kii->http_context),
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
prv_http_request(
        kii_core_t* kii,
        const char* method,
        const char* resource_path,
        const char* content_type,
        const char* access_token,
        const char* etag,
        const char* body)
{
    kii_http_client_code_t result;
    result = kii->http_set_request_line_cb(
            &(kii->http_context),
            method,
            kii->app_host,
            resource_path);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
        return KIIE_FAIL;
    }

    result = kii->http_set_header_cb(
            &(kii->http_context),
            "x-kii-appid",
            kii->app_id);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }

    result = kii->http_set_header_cb(
            &(kii->http_context),
            "x-kii-appkey",
            kii->app_key);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        return KIIE_FAIL;
    }

    if (content_type != NULL) {
        result = kii->http_set_header_cb(
                &(kii->http_context),
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
        result = kii->http_set_header_cb(
                &(kii->http_context),
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
                &(kii->http_context),
                "if-match",
                etag 
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            return KIIE_FAIL;
        }
    }

    if (body != NULL) {
        size_t body_len;
        char content_length[8];
        body_len = kii_strlen(body);
        kii_memset(content_length, 0x00, 8);
        prv_content_length_str(body_len, content_length, 8);
        result = kii->http_set_header_cb(
                &(kii->http_context),
                "content-length",
                content_length
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            return KIIE_FAIL;
        }

        result = kii->http_set_body_cb(
                &(kii->http_context),
                body, body_len);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_BODY_CB_FAILED);
            return KIIE_FAIL;
        }
    } else {
        result = kii->http_set_body_cb(
                &(kii->http_context),
                NULL, 0);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_BODY_CB_FAILED);
            return KIIE_FAIL;
        }
    }
	kii->http_context.total_send_size = strlen(kii->http_context.buffer);
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
    char body[256];

    prv_set_auth_path(kii);
    kii_memset(body, 0x00, sizeof(body));
    kii_sprintf(body,
            "{\"username\":\"VENDOR_THING_ID:%s\", \"password\": \"%s\"}",
            vendor_thing_id,
            password);

    result = prv_http_request(
            kii,
            "POST",
            kii->_http_request_path,
            "application/json",
            NULL,
            NULL,
            body
            );

    if (result == KIIE_OK) {
        kii->_state = KII_STATE_READY;
    }
    return result;
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
    char body[256];
    char* access_token;
    char* c_development;
    M_ACCESS_TOKEN(access_token, kii->author.access_token);

    c_development = ((development == KII_TRUE) ? ("true") : ("false"));
    prv_set_installation_path(kii);

    kii_memset(body, 0x00, 256);
    kii_sprintf(body,
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

    result = kii->http_set_request_line_cb(
            &(kii->http_context),
            http_method,
            kii->app_host,
            resource_path);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
        return KIIE_FAIL;
    }

    /* set app id */
    result = kii->http_set_header_cb(
            &(kii->http_context),
            "x-kii-appid",
            kii->app_id);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        goto exit;
    }

    /* set app key */
    result = kii->http_set_header_cb(
            &(kii->http_context),
            "x-kii-appkey",
            kii->app_key);
    if (result != KII_HTTPC_OK) {
        M_KII_LOG(M_REQUEST_HEADER_CB_FAILED);
        goto exit;
    }

    /* set content-type */
    if (content_type != NULL) {
        result = kii->http_set_header_cb(
                &(kii->http_context),
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
        result = kii->http_set_header_cb(
                &(kii->http_context),
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
        result = kii->http_set_header_cb(
                &(kii->http_context),
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
            result = kii->http_set_header_cb(
                    &(kii->http_context),
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
        result = kii->http_set_header_cb(
                &(kii->http_context),
                "content-length",
                content_length
                );
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_LINE_CB_FAILED);
            goto exit;
        }
        result = kii->http_set_body_cb(&(kii->http_context), http_body,
                body_size);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_BODY_CB_FAILED);
            goto exit;
        } else {
            kii->http_context.total_send_size =
                strlen(kii->http_context.buffer);
        }
    } else {
        result = kii->http_set_body_cb(
                &(kii->http_context),
                NULL, 0);
        if (result != KII_HTTPC_OK) {
            M_KII_LOG(M_REQUEST_BODY_CB_FAILED);
            goto exit;
        } else {
			kii->http_context.total_send_size = strlen(kii->http_context.buffer);
		} 
    }
    kii->_state = KII_STATE_READY;
    ret = KIIE_OK;
exit:
    va_end(ap);
    return ret;
}
/* vim:set ts=4 sts=4 sw=4 et fenc=UTF-8 ff=unix: */
