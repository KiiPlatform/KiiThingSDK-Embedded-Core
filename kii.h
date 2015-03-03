#ifndef _kii_
#define _kii_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

typedef enum kii_bool_t {
    KII_FALSE = 0,
    KII_TRUE
} kii_bool_t;

typedef enum kii_http_client_code_t {
    KII_HTTPC_OK = 0,
    KII_HTTPC_FAIL,
    KII_HTTPC_AGAIN
} kii_http_client_code_t;

typedef kii_http_client_code_t
        (*KII_HTTPCB_SET_REQUEST_LINE_PTR)(
                void* http_context,
                const char* method,
                const char* host,
                const char* path);
typedef kii_http_client_code_t
        (*KII_HTTPCB_SET_HEADER_PTR)(
                void* http_context,
                const char* key,
                const char* value);
typedef kii_http_client_code_t
        (*KII_HTTPCB_SET_BODY_PTR)(
                void* http_context,
                const char* body_data);
typedef kii_http_client_code_t
        (*KII_HTTPCB_EXECUTE)(
                void* http_context,
                int* response_code,
                char** response_body);

typedef void
        (*KII_LOGGER)(
                const char* format,
                ...
                );

typedef enum kii_error_code_t {
    KIIE_OK = 0,
    KIIE_FAIL
} kii_error_code_t;

typedef enum kii_state_t {
    KII_STATE_IDLE = 0,
    KII_STATE_READY,
    KII_STATE_EXECUTE
} kii_state_t;

typedef struct kii_t
{
    char* app_id;
    char* app_key;
    char* app_host;
    char* buffer;
    size_t buffer_size;
    int response_code;
    char* response_body;

    void* http_context;
    KII_HTTPCB_SET_REQUEST_LINE_PTR http_set_request_line_cb;
    KII_HTTPCB_SET_HEADER_PTR http_set_header_cb;
    KII_HTTPCB_SET_BODY_PTR http_set_body_cb;
    KII_HTTPCB_EXECUTE http_execute_cb;
    KII_LOGGER logger_cb;
    char _http_request_path[256];

    kii_state_t _state;
} kii_t;

typedef struct kii_error_t
{
    char* error_code;
    char* error_message;
} kii_error_t;

typedef struct kii_thing_t
{
    char* vendor_thing_id;
    char* thing_id;
    char* access_token;
} kii_thing_t;

typedef enum kii_scope_type_t {
    KII_SCOPE_APP,
    KII_SCOPE_USER,
    KII_SCOPE_GROUP,
    KII_SCOPE_THING
} kii_scope_type_t;

typedef struct kii_bucket_t {
    kii_scope_type_t scope;
    char* scope_id;
    char* bucket_name;
} kii_bucket_t;

typedef struct kii_topic_t {
    kii_scope_type_t scope;
    char* scope_id;
    char* topic_name;
} kii_topic_t;

kii_state_t kii_get_state(kii_t* kii);
kii_error_code_t kii_run(kii_t* kii);

kii_error_code_t
kii_register_thing(kii_t* kii,
        const char* thing_data);

kii_error_code_t
kii_create_new_object(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_data);

kii_error_code_t
kii_create_new_object_with_id(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* object_data);

kii_error_code_t
kii_patch_object(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* patch_data,
        const char* opt_etag);

kii_error_code_t
kii_replace_object(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_id,
        const char* replace_data,
        const char* opt_etag);

kii_error_code_t
kii_get_object(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_id);

kii_error_code_t
kii_delete_object(
        kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket,
        const char* object_id);

kii_error_code_t
kii_subscribe_bucket(kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket);

kii_error_code_t
kii_unsubscribe_bucket(kii_t* kii,
        const char* access_token,
        const kii_bucket_t* bucket);

kii_error_code_t
kii_subscribe_topic(kii_t* kii,
        const char* access_token,
        const kii_topic_t* topic);

kii_error_code_t
kii_unsubscribe_topic(kii_t* app,
        const char* access_token,
        const kii_topic_t* topic);

kii_error_code_t
kii_install_thing_push(kii_t* kii,
        const char* access_token,
        kii_bool_t development);

kii_error_code_t
kii_get_mqtt_endpoint(kii_t* kii,
        const char* access_token,
        const char** installation_id);

#ifdef __cplusplus
}
#endif

#endif
