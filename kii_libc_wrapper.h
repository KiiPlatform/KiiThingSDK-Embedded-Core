#ifndef _kii_libc_wrapper
#define _kii_libc_wrapper

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

typedef size_t kii_size_t;

void kii_assert(int expression);
void *kii_memset(void *buf, int ch, size_t n);
size_t kii_strlen(const char *s);
char *kii_strcat(char *s1, const char *s2);
int kii_sprintf(char *str, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
