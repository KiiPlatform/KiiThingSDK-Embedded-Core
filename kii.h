#ifndef _kii_
#define _kii_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum kii_bool_t {
    KII_FALSE = 0,
    KII_TRUE
} kii_bool_t;

typedef kii_bool_t (*KII_CB_CONNECT_PTR)(void* app_context, const char* host, const char* path);
typedef kii_bool_t (*KII_CB_SEND_PTR)(void* app_context, const char* send_buff, int buff_length);
typedef kii_bool_t (*KII_CB_RECV_PTR)(void* app_context, char* recv_buff, int length_to_read, int* out_actual_length);
typedef kii_bool_t (*KII_CB_CLOSE_PTR)(void* app_context);

typedef enum kii_error_code_t {
    KIIE_OK = 0,
    KIIE_FAIL
} kii_error_code_t;

typedef enum kii_state_t {
    KII_STATE_IDLE = 0,
    KII_STATE_CONNECT,
    KII_STATE_SEND,
    KII_STATE_RECV,
    KII_STATE_CLOSE
} kii_state_t;

typedef struct kii_t
{
    char* app_id;
    char* app_key;
    char* app_host;
    char* buffer;
    int buffer_size;
    char request_url[256];
    KII_CB_CONNECT_PTR callback_connect_ptr;
    KII_CB_SEND_PTR callback_send_ptr;
    KII_CB_RECV_PTR callback_recv_ptr;
    KII_CB_CLOSE_PTR callback_close_ptr;
    void* app_context;

    /* private properties */
    /* TODO: hide from public headers */
    kii_state_t _state;
    int _last_chunk;
    int _sent_size;
    int _received_size;

} kii_t;

kii_state_t kii_get_state(kii_t* kii);
kii_error_code_t kii_run(kii_t* kii);

kii_error_code_t
kii_register_thing(kii_t* kii,
        const char* thing_data);

kii_error_code_t
kii_create_new_object(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_data);

kii_error_code_t
kii_create_new_object_with_id(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_id,
        const char* object_data);

kii_error_code_t
kii_patch_object(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_id,
        const char* patch_data,
        const char* opt_etag);

kii_error_code_t
kii_replace_object(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_id,
        const char* replace_data,
        const char* opt_etag);

kii_error_code_t
kii_get_object(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_id);

kii_error_code_t
kii_delete_object(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name,
        const char* object_id);

kii_error_code_t
kii_subscribe_bucket(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name);

kii_error_code_t
kii_unsubscribe_bucket(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* bucket_name);

kii_error_code_t
kii_subscribe_topic(kii_t* kii,
        const char* access_token,
        const char* thing_id,
        const char* topic_name);

kii_error_code_t
kii_unsubscribe_topic(kii_t* app,
        const char* access_token,
        const char* thing_id,
        const char* topic_name);

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
