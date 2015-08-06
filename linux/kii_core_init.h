#ifndef __KII_CORE_INIT
#define __KII_CORE_INIT

#ifdef __cplusplus
extern "C" {
#endif

#include <kii_core.h>

void kii_core_init(
        kii_core_t* kii,
        char* app_host,
        char* app_id,
        char* app_key,
        char* buff,
        size_t length);

#ifdef __cplusplus
}
#endif

#endif
