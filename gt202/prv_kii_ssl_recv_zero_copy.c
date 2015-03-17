#include <gt202_kii_adapter.h>

#include "prv_kii_ssl_setting.h"

#if !ZERO_COPY
#error
#endif

    kii_http_client_code_t
prv_ssl_recv(
        void* app_context,
        char* recv_buff,
        int length_to_read,
        int* out_actual_length)
{
    int ret = KII_HTTPC_FAIL;
    int res;
    int received;
    int total = 0;
    char *pBuf = NULL;
    context_t* ctx = (context_t*)app_context;
    do
    {
        res = t_select((void *)handle, ctx->sock, 1000);
        if (res == A_OK)
        {
#if CONNECT_SSL
            received = SSL_read(ctx->ssl, (void**)&pBuf, length_to_read);
#else
            received = t_recv(handle, ctx->sock, (void**)&pBuf, length_to_read, 0);
#endif
            if(received > 0)
            {
                memcpy(recv_buff, pBuf, received);
                zero_copy_free(pBuf);
                total = received;
                break;
            }
        }
    } while (res == A_OK);

    if (total >  0) {
        *out_actual_length = total;
        return KII_HTTPC_OK;
    } else {
        printf("failed to receive:\n");
        // TOOD: could be 0 on success?
        *out_actual_length = 0;
        return KII_HTTPC_FAIL;
    }
}

