#ifndef _STDLIB_H
#define _STDLIB_H

#include <stddef.h>

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void  free(void *ptr);
void  abort(void);
void  exit(int code);
int   abs(int x);
long  labs(long x);

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#endif
