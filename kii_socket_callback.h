#ifndef _KII_SOCKET_CALLBACK
#define _KII_SOCKET_CALLBACK

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kii_socket_context_t {
    void* app_context;
} kii_socket_context_t;

typedef enum kii_socket_code_t {
    KII_SOCKETC_OK,
    KII_SOCKETC_FAIL,
    KII_SOCKETC_AGAIN
} kii_socket_code_t;

typedef kii_socket_code_t
    (*KII_SOCKET_CONNECT_CB)
    (kii_socket_context_t* socket_context, const char* host);
typedef kii_socket_code_t
    (*KII_SOCKET_SEND_CB)
    (kii_socket_context_t* socket_context, const char* buffer, size_t length);
typedef kii_socket_code_t
    (*KII_SOCKET_RECV_CB)
    (kii_socket_context_t* socket_context, char* buffer, size_t length_to_read,
     size_t* out_actual_length);
typedef kii_socket_code_t
    (*KII_SOCKET_CLOSE_CB)(kii_socket_context_t* socket_context);


#ifdef _cplusplus
}
#endif

#endif /* _KII_SOCKET_CALBACK */
