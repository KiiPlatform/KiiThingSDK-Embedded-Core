#include "kii.h"

kii_bool_t my_connect(void* app_context, const char* host, const char* path)
{
    /* TODO: implement. */
    return KII_TRUE;
}

kii_bool_t my_send(void* app_context, const char* send_buff, int buff_length)
{
    /* TODO: implement. */
    return KII_TRUE;
}

kii_bool_t my_recv(void* app_context, char* recv_buff, int length_to_read, int* out_actual_length)
{
    /* TODO: implement. */
    return KII_TRUE;
}


kii_bool_t my_close(void* app_context)
{
    /* TODO: implement. */
    return KII_TRUE;
}

void parse_response(char* buff)
{
    /* TODO: implement */
    /* buff : raw http response */
}

int main()
{
    kii_t kii;
    kii_state_t state;
    kii_error_code_t err;
    char buff[4096];
    char thingData[] = "{\"_vendorThindID\":\"thing-xxx-yyy\", \"_password\":\"1234\"}";

    /* Initialization */
    kii.app_id = "my-app-id";
    kii.app_key = "my-app-key";
    kii.app_host = "api-jp.kii.com";
    kii.buffer = buff;
    kii.callback_connect_ptr = &my_connect;
    kii.callback_send_ptr = &my_send;
    kii.callback_recv_ptr = &my_recv;
    kii.callback_close_ptr = &my_close;

    /* Register Thing */
    err = kii_register_thing(&kii, thingData);
    if (err != KIIE_OK) {
        return 1;
    }
    while (1) {
        err = kii_run(&kii);
        state = kii_get_state(&kii);
        if (state == KII_STATE_IDLE) {
            /* End of operation. */
            break;
        }
    }
    if (err != KIIE_OK) {
        return 1;
    }
    parse_response(kii.buffer);
}

