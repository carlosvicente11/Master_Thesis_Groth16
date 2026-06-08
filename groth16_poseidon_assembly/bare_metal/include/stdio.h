#ifndef _STDIO_H
#define _STDIO_H

#include <stddef.h>
#include <stdarg.h>

typedef struct { int fd; } FILE;
extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

int    printf(const char *fmt, ...);
int    vprintf(const char *fmt, va_list ap);
int    snprintf(char *buf, size_t size, const char *fmt, ...);
int    fprintf(FILE *f, const char *fmt, ...);
int    fflush(FILE *f);
FILE  *fopen(const char *path, const char *mode);
size_t fread(void *buf, size_t elem, size_t count, FILE *f);
int    fclose(FILE *f);

#define EOF (-1)
#define NULL ((void*)0)

#endif
