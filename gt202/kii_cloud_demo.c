#include "kii_cloud_demo.h"
#include "kii_cloud_demo_setting.h"

#include "gt202_kii_adapter.h"

void parse_response(char* resp_body)
{
    /* TODO: implement */
}

static void init(kii_t* kii, context_t* ctx, char* buff, int buff_length)
{
    memset(kii, 0x00, sizeof(kii_t));
    kii->app_id = APP_ID;
    kii->app_key = APP_KEY;
    kii->app_host = APP_HOST;
    kii->buffer = buff;
    kii->buffer_size = buff_length;

    kii->http_context = ctx;
    kii->http_set_request_line_cb = request_line_cb;
    kii->http_set_header_cb = header_cb;
    kii->http_set_body_cb = body_cb;
    kii->http_execute_cb = execute_cb;
    kii->logger_cb = logger_cb;

    memset(ctx, 0x00, sizeof(context_t));
    /* share the request and response buffer.*/
    ctx->buff = buff;
    ctx->buff_size = buff_length;
}

static void set_author(kii_t* kii, kii_author_t* author)
{
    memset(author, 0x00, sizeof(kii_author_t));
    author->author_id = THING_ID;
    author->access_token = ACCESS_TOKEN;
    kii->author = author;
}

static void init_bucket(kii_bucket_t* bucket) {
    memset(bucket, 0x00, sizeof(kii_bucket_t));
    bucket->scope = KII_SCOPE_THING;
    bucket->scope_id = THING_ID;
    bucket->bucket_name = BUCKET_NAME;
}

static void init_topic(kii_topic_t* topic) {
    memset(topic, 0x00, sizeof(kii_topic_t));
    topic->scope = KII_SCOPE_THING;
    topic->scope_id = THING_ID;
    topic->topic_name = TOPIC_NAME;
}

static void print_response(kii_t* kii)
{
    printf("========response========\n");
    printf("%s\n", kii->buffer);
    printf("========response========\n");
    printf("response_code: %d\n", kii->response_code);
    printf("response_body:\n%s\n", kii->response_body);
}

static int register_thing(kii_t* kii)
{
    int ret = 0;
    kii_state_t state;
    kii_error_code_t err;
    char *thingData = malloc(1024);
    
    /* Prepare Thing Data */
    memset(thingData, 0x00, 1024);
    sprintf(thingData,
            "{\"_vendorThingID\":\"%d\", \"_password\":\"1234\"}",
            time(NULL));
    /* Register Thing */
    err = kii_register_thing(kii, thingData);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        ret = 1;
        goto END_FUNC;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        ret = 1;
        goto END_FUNC;
    }
    print_response(kii);
    parse_response(kii->response_body);

END_FUNC:
    free(thingData);
    return ret;
}

static int create_new_object(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;
    
    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_create_new_object(
            kii,
            &bucket,
            "{}",
            NULL);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int create_new_object_with_id(kii_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;
    
    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_create_new_object_with_id(
            kii,
            &bucket,
            id,
            "{}",
            NULL);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int patch_object(kii_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_patch_object(
            kii,
            &bucket,
            id,
            "{}",
            NULL);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int replace_object(kii_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_replace_object(
            kii,
            &bucket,
            id,
            "{}",
            NULL);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int get_object(kii_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_get_object(
            kii,
            &bucket,
            id);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int delete_object(kii_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_delete_object(
            kii,
            &bucket,
            id);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int subscribe_bucket(kii_t* kii, const char* bucket_name)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_subscribe_bucket(
            kii,
            &bucket);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int unsubscribe_bucket(kii_t* kii, const char* bucket_name)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    init_bucket(&bucket);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_unsubscribe_bucket(
            kii,
            &bucket);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int create_topic(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    init_topic(&topic);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_create_topic(
            kii,
            &topic);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int delete_topic(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    init_topic(&topic);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_delete_topic(
            kii,
            &topic);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int subscribe_topic(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    init_topic(&topic);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_subscribe_topic(
            kii,
            &topic);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int unsubscribe_topic(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    init_topic(&topic);
    kii_author_t author;
    set_author(kii, &author);

    err = kii_unsubscribe_topic(
            kii,
            &topic);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int install_push(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_author_t author;
    set_author(kii, &author);

    err = kii_install_thing_push(
            kii,
            KII_FALSE);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int get_endpoint(kii_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_author_t author;
    set_author(kii, &author);

    err = kii_get_mqtt_endpoint(
            kii,
            INSTALLATION_ID);
    printf("request:\n%s\n", kii->buffer);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_run(kii);
        state = kii_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

#define CMD_INDEX 1

int kii_main(int argc, char *argv[])
{
    int ret = A_ERROR;
    context_t *ctx = NULL;
    kii_t *kii = NULL;
    kii_state_t state;
    kii_error_code_t err;
    char *buff = NULL;

    if (argc < CMD_INDEX + 1)
    {
        return A_ERROR;
    }

    kii = malloc(sizeof(kii_t));
    ctx = malloc(sizeof(context_t));
    buff = malloc(4096);

    init(kii, ctx, buff, 4096);

    if(ATH_STRCMP(argv[CMD_INDEX], "register") == 0)
    {
        if (register_thing(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "new-object") == 0)
    {
        if (create_new_object(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "new-object-with-id") == 0)
    {
        if (create_new_object_with_id(kii, OBJECT_NAME) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "patch-object") == 0)
    {
        if (patch_object(kii, OBJECT_NAME) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "replace-object") == 0)
    {
        if (replace_object(kii, OBJECT_NAME) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "get-object") == 0)
    {
        if (get_object(kii, OBJECT_NAME) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "delete-object") == 0)
    {
        if (delete_object(kii, OBJECT_NAME) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "subscribe-bucket") == 0)
    {
        if (subscribe_bucket(kii, BUCKET_NAME) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "unsubscribe-bucket") == 0)
    {
        if (unsubscribe_bucket(kii, BUCKET_NAME) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "create-topic") == 0)
    {
        if (create_topic(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "delete-topic") == 0)
    {
        if (delete_topic(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "subscribe-topic") == 0)
    {
        if (subscribe_topic(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "unsubscribe-topic") == 0)
    {
        if (unsubscribe_topic(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "install-push") == 0)
    {
        if (install_push(kii) == 0)
        {
            ret = A_OK;
        }
    }
    else if(ATH_STRCMP(argv[CMD_INDEX], "get-endpoint") == 0)
    {
        if (get_endpoint(kii) == 0)
        {
            ret = A_OK;
        }
    }

    free(kii);
    free(buff);
    free(ctx);
    return ret;
}

