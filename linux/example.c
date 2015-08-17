#include <kii_core.h>
#include "example.h"
#include "kii_core_init.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <getopt.h>

void parse_response(char* resp_body)
{
    /* TODO: implement */
}

static void set_author(kii_core_t* kii, kii_author_t* author)
{
    memset(author, 0x00, sizeof(kii_author_t));
    strncpy(author->author_id, (char*)EX_THING_ID, 128);
    strncpy(author->access_token, (char*)EX_ACCESS_TOKEN, 128);
    kii->author = *author;
}

static void init_bucket(kii_bucket_t* bucket) {
    memset(bucket, 0x00, sizeof(kii_bucket_t));
    bucket->scope = KII_SCOPE_THING;
    bucket->scope_id = (char*)EX_THING_ID;
    bucket->bucket_name = (char*)EX_BUCKET_NAME;
}

static void init_topic(kii_topic_t* topic) {
    memset(topic, 0x00, sizeof(kii_topic_t));
    topic->scope = KII_SCOPE_THING;
    topic->scope_id = (char*)EX_THING_ID;
    topic->topic_name = (char*)EX_TOPIC_NAME;
}

static void print_request(kii_core_t* kii)
{
    printf("========request========\n");
    printf("%s\n", kii->http_context.buffer);
    printf("========request========\n");
}

static void print_response(kii_core_t* kii)
{
    printf("========response========\n");
    printf("%s\n", kii->http_context.buffer);
    printf("========response========\n");
    printf("response_code: %d\n", kii->response_code);
    printf("response_body:\n%s\n", kii->response_body);
}

static int register_thing(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;
    pid_t pid;
    char thingData[1024];

    /* Prepare Thing Data */
    memset(thingData, 0x00, 1024);
    pid = getpid();
    sprintf(thingData,
            "{\"_vendorThingID\":\"%d\", \"_password\":\"1234\"}",
            pid);
    /* Register Thing */
    err = kii_core_register_thing(kii, thingData);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int register_thing_with_id(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;
    pid_t pid;
    char vendor_thing_id[32];
    
    /* Prepare Thing Data */
    memset(vendor_thing_id, 0x00, sizeof(vendor_thing_id));
    pid = getpid();
    sprintf(vendor_thing_id, "%d", pid);
    /* Register Thing */
    err = kii_core_register_thing_with_id(kii, vendor_thing_id, "1234",
            "my_type");
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int thing_authentication(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    err = kii_core_thing_authentication(
            kii,
            EX_AUTH_VENDOR_ID,
            EX_AUTH_VENDOR_PASS);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int create_new_object(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;
    
    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_create_new_object(
            kii,
            &bucket,
            EX_OBJECT_DATA,
            NULL);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int create_new_object_with_id(kii_core_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;
    
    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_create_new_object_with_id(
            kii,
            &bucket,
            id,
            EX_OBJECT_DATA,
            NULL);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int patch_object(kii_core_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_patch_object(
            kii,
            &bucket,
            id,
            EX_OBJECT_DATA,
            NULL);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int replace_object(kii_core_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_replace_object(
            kii,
            &bucket,
            id,
            EX_OBJECT_DATA,
            NULL);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }    
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int get_object(kii_core_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_get_object(
            kii,
            &bucket,
            id);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int delete_object(kii_core_t* kii, const char* id)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_delete_object(
            kii,
            &bucket,
            id);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int subscribe_bucket(kii_core_t* kii, const char* bucket_name)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_subscribe_bucket(
            kii,
            &bucket);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int unsubscribe_bucket(kii_core_t* kii, const char* bucket_name)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_bucket_t bucket;
    kii_author_t author;

    init_bucket(&bucket);
    set_author(kii, &author);

    err = kii_core_unsubscribe_bucket(
            kii,
            &bucket);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int create_topic(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    kii_author_t author;

    init_topic(&topic);
    set_author(kii, &author);

    err = kii_core_create_topic(
            kii,
            &topic);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int delete_topic(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    kii_author_t author;

    init_topic(&topic);
    set_author(kii, &author);

    err = kii_core_delete_topic(
            kii,
            &topic);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int subscribe_topic(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    kii_author_t author;

    init_topic(&topic);
    set_author(kii, &author);

    err = kii_core_subscribe_topic(
            kii,
            &topic);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int unsubscribe_topic(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_topic_t topic;
    kii_author_t author;

    init_topic(&topic);
    set_author(kii, &author);

    err = kii_core_unsubscribe_topic(
            kii,
            &topic);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int install_push(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_author_t author;
    set_author(kii, &author);

    err = kii_core_install_thing_push(
            kii,
            KII_FALSE);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int get_endpoint(kii_core_t* kii)
{
    kii_state_t state;
    kii_error_code_t err;

    kii_author_t author;
    set_author(kii, &author);

    err = kii_core_get_mqtt_endpoint(
            kii,
            EX_MQTT_ENDPOINT);
    print_request(kii);
    if (err != KIIE_OK) {
        printf("execution failed\n");
        return 1;
    }
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

static int thing_api_call_example_auth(kii_core_t* kii)
{
    kii_error_code_t err;
    kii_state_t state;

    if (kii_core_api_call_start(kii, "POST", "api/oauth2/token",
                    "application/json", KII_FALSE) != KIIE_OK) {
        printf("execution failed.\n");
        return 1;
    }
    if (kii_core_api_call_append_body(kii, "{\"username\":\"VENDOR_THING_ID:",
                    strlen("{\"username\":\"VENDOR_THING_ID:")) != KIIE_OK) {
        printf("execution failed.\n");
        return 1;
    }
    if (kii_core_api_call_append_body(kii, EX_AUTH_VENDOR_ID,
                    strlen(EX_AUTH_VENDOR_ID)) != KIIE_OK) {
        printf("execution failed.\n");
        return 1;
    }
    if (kii_core_api_call_append_body(kii, "\",\"password\":\"",
                    strlen("\",\"password\":\"")) != KIIE_OK) {
        printf("execution failed.\n");
        return 1;
    }
    if (kii_core_api_call_append_body(kii, EX_AUTH_VENDOR_PASS,
                    strlen(EX_AUTH_VENDOR_PASS)) != KIIE_OK) {
        printf("execution failed.\n");
        return 1;
    }
    if (kii_core_api_call_append_body(kii, "\"}", strlen("\"}")) != KIIE_OK) {
        printf("execution failed.\n");
        return 1;
    }

    if (kii_core_api_call_end(kii) != KIIE_OK) {
        printf("execution failed.\n");
        return 1;
    }

    print_request(kii);
    do {
        err = kii_core_run(kii);
        state = kii_core_get_state(kii);
    } while (state != KII_STATE_IDLE);
    if (err != KIIE_OK) {
        printf("execution failed.\n");
        return 1;
    }
    print_response(kii);
    parse_response(kii->response_body);
    return 0;
}

int main(int argc, char** argv)
{
    kii_core_t kii;
    char buff[EX_BUFFER_SIZE];

    int optval;

    /* Initialization */
    kii_core_impl_init(&kii, (char *)EX_APP_HOST, (char *)EX_APP_ID,
            (char *)EX_APP_KEY, buff, EX_BUFFER_SIZE);

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"register", no_argument, NULL,  0},
            {"new-object", no_argument, NULL, 1},
            {"new-object-with-id", no_argument, NULL, 2},
            {"patch-object", no_argument, NULL, 3},
            {"replace-object", no_argument, NULL, 4},
            {"get-object", no_argument, NULL, 5},
            {"delete-object", no_argument, NULL, 6},
            {"subscribe-bucket", no_argument, NULL, 7},
            {"unsubscribe-bucket", no_argument, NULL, 8},
            {"create-topic", no_argument, NULL, 9},
            {"delete-topic", no_argument, NULL, 10},
            {"subscribe-topic", no_argument, NULL, 11},
            {"unsubscribe-topic", no_argument, NULL, 12},
            {"install-push", no_argument, NULL, 13},
            {"get-endpoint", no_argument, NULL, 14},
            {"authentication", no_argument, NULL,  15},
            {"api", no_argument, NULL,  16},
            {"register-with-id", no_argument, NULL,  17},
            {"api-call-example-auth", no_argument, NULL, 18},
            {"help", no_argument, NULL, 1000},
            {0, 0, 0, 0}
        };

        optval = getopt_long(argc, argv, "",
                 long_options, &option_index);
        if (optval == -1)
            break;

        switch (optval) {
        case 0:
            printf("register thing\n");
            register_thing(&kii);
            break;
        case 1:
            printf("create new object\n");
            create_new_object(&kii);
            break;
        case 2:
            printf("create new object with id\n");
            create_new_object_with_id(&kii, EX_OBJECT_ID);
            break;
        case 3:
            printf("patch object\n");
            patch_object(&kii, EX_OBJECT_ID);
            break;
        case 4:
            printf("replace object\n");
            replace_object(&kii, EX_OBJECT_ID);
            break;
        case 5:
            printf("get object\n");
            get_object(&kii, EX_OBJECT_ID);
            break;
        case 6:
            printf("delete object\n");
            delete_object(&kii, EX_OBJECT_ID);
            break;
        case 7:
            printf("subscribe bucket\n");
            subscribe_bucket(&kii, EX_BUCKET_NAME);
            break;
        case 8:
            printf("unsubscribe bucket\n");
            unsubscribe_bucket(&kii, EX_BUCKET_NAME);
            break;
        case 9:
            printf("create topic\n");
            create_topic(&kii);
            break;
        case 10:
            printf("delete topic\n");
            delete_topic(&kii);
            break;
        case 11:
            printf("subscribe topic\n");
            subscribe_topic(&kii);
            break;
        case 12:
            printf("unsubscribe topic\n");
            unsubscribe_topic(&kii);
            break;
        case 13:
            printf("install push\n");
            install_push(&kii);
            break;
        case 14:
            printf("get endpoint\n");
            get_endpoint(&kii);
            break;
        case 15:
            printf("authentication\n");
            thing_authentication(&kii);
            break;
        case 16:
            printf("api\n");
            kii_core_api_call(&kii, "GET", "hoge/fuga", "body", 4, "text/plain",
                    "x-kii-http-header1:value", "x-kii-http-header2:value2", NULL);
            print_request(&kii);
            break;
        case 17:
            printf("register with id\n");
            register_thing_with_id(&kii);
            break;
        case 18:
            printf("api call example authentication\n");
            thing_api_call_example_auth(&kii);
            break;
        case 1000:
            printf("to configure parameters, edit example.h\n\n");
            printf("commands: \n");
            printf("--register\n register new thing.\n");
            printf("--authentication\n get access token.\n");
            printf("--new-object\n create new object.\n");
            printf("--new-object-with-id\n create new object with id.\n");
            printf("--patch-object\n patch object.\n");
            printf("--replace-object\n replace object.\n");
            printf("--get-object\n get object.\n");
            printf("--delete-object\n delete object.\n");
            printf("--subscribe-bucket\n subscribe bucket.\n");
            printf("--unsubscribe-bucket\n unsubscribe bucket.\n");
            printf("--create-topic\n create topic.\n");
            printf("--delete-topic\n delete topic.\n");
            printf("--subscribe-topic\n subscribe to topic.\n");
            printf("--unsubscribe-topic\n unsubscribe to topic.\n");
            printf("--install-push\n install push.\n");
            printf("--get-endpoint\n get endpoint of MQTT.\n");
            printf("--api-call-example-auth\n api call example for authentication.\n");
            break;
            
        case '?':
            break;
        default:
            printf("?? getopt returned character code 0%o ??\n", optval);
        }
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
    }
    return 0;
}

