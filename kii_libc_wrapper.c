#include "kii_libc_wrapper.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

void kii_assert(int expression)
{
    assert(expression);
}

void *kii_memset(void *buf, int ch, size_t n)
{
    return memset(buf, ch, n);
}

size_t kii_strlen(const char *s)
{
    return strlen(s);
}

char *kii_strcat(char *s1, const char *s2)
{
    return strcat(s1, s2);
}

int kii_sprintf(char *str, const char *format, ...)
{
    int res;
    va_list ap;

    va_start(ap, format);
    res = vsprintf(str, format, ap);
    va_end(ap);

    return res;
}

