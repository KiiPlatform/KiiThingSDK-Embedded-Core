#include "kii.h"

kii_state_t
kii_get_state(kii_t* kii)
{
    /* TODO: implement. */
    return KII_STATE_IDLE;
}

kii_error_code_t
kii_run(kii_t* kii)
{
    /* TODO: implement. */
    return KIIE_FAIL;
}

kii_error_code_t
kii_register_thing(kii_t* kii,
        const char* thing_data)
{
    /* TODO: implement. */
    return KIIE_FAIL;
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

