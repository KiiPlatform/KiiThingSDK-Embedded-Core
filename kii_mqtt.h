#ifndef _KII_MQTT
#define _KII_MQTT

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kii_mqtt_endpoint_t {
    char username[64];
    char password[64];
    char topic[64];
    char host[64];
    unsigned int port_tcp;
    unsigned int port_ssl;
    unsigned long ttl;
} kii_mqtt_endpoint_t;

#ifdef __cplusplus
}
#endif

#endif /* _KII_MQTT */
