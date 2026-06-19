#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

extern int main(void);
extern uint32_t __bss_start, __bss_end;
extern uint32_t _stack_top;

/* ARM semihosting: BKPT #0xAB on Cortex-M */
static inline int semihost_call(int op, void *arg) {
    register int r0 __asm__("r0") = op;
    register void *r1 __asm__("r1") = arg;
    __asm__ volatile("bkpt #0xAB" : "+r"(r0) : "r"(r1) : "memory");
    return r0;
}

/* Semihosting operations */
#define SYS_OPEN     0x01
#define SYS_CLOSE    0x02
#define SYS_WRITE    0x05
#define SYS_READ     0x06
#define SYS_FLEN     0x0C
#define SYS_EXIT     0x18
#define SYS_WRITEC   0x03

static void Default_Handler(void) {
    while (1) {}
}

void __attribute__((weak, alias("Default_Handler"))) SysTick_Handler(void);

void _start(void) {
    /* Zero BSS */
    uint32_t *p = &__bss_start;
    while (p < &__bss_end) *p++ = 0;

    int rc = main();

    /* Semihosting exit */
    uint32_t args[2] = {0x20026, (uint32_t)rc};  /* ADP_Stopped_ApplicationExit */
    semihost_call(SYS_EXIT, args);
    while (1) {}
}

/* Cortex-M4 vector table (16 system exceptions) */
__attribute__((section(".isr_vector"), used))
const void *vector_table[] = {
    &_stack_top,        /*  0: Initial SP */
    _start,             /*  1: Reset */
    Default_Handler,    /*  2: NMI */
    Default_Handler,    /*  3: HardFault */
    Default_Handler,    /*  4: MemManage */
    Default_Handler,    /*  5: BusFault */
    Default_Handler,    /*  6: UsageFault */
    (void *)0,          /*  7: Reserved */
    (void *)0,          /*  8: Reserved */
    (void *)0,          /*  9: Reserved */
    (void *)0,          /* 10: Reserved */
    Default_Handler,    /* 11: SVCall */
    Default_Handler,    /* 12: DebugMon */
    (void *)0,          /* 13: Reserved */
    Default_Handler,    /* 14: PendSV */
    SysTick_Handler,    /* 15: SysTick */
};

/* --- Minimal libc for RELIC --- */

static int stdout_fd = -1;

static void ensure_stdout(void) {
    if (stdout_fd >= 0) return;
    uint32_t args[3] = { (uint32_t)":tt", 4, 3 };  /* stdout, write mode */
    stdout_fd = semihost_call(SYS_OPEN, args);
}

int _write(int fd, const char *buf, int len) {
    (void)fd;
    ensure_stdout();
    uint32_t args[3] = { (uint32_t)stdout_fd, (uint32_t)buf, (uint32_t)len };
    int not_written = semihost_call(SYS_WRITE, args);
    return len - not_written;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = s;
    while (n--) *p++ = (uint8_t)c;
    return s;
}

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    uint8_t *d = dst;
    const uint8_t *s = src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n; s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *pa = a, *pb = b;
    for (size_t i = 0; i < n; i++) {
        if (pa[i] != pb[i]) return pa[i] - pb[i];
    }
    return 0;
}

size_t strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}

char *strcpy(char *dst, const char *src) {
    char *d = dst;
    while ((*d++ = *src++));
    return dst;
}

int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

char *strchr(const char *s, int c) {
    while (*s) { if (*s == c) return (char *)s; s++; }
    return NULL;
}

int strncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
        if (a[i] == '\0') return 0;
    }
    return 0;
}

char *strrchr(const char *s, int c) {
    const char *last = NULL;
    while (*s) { if (*s == c) last = s; s++; }
    return (char *)last;
}

char *strncpy(char *dst, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i]; i++) dst[i] = src[i];
    for (; i < n; i++) dst[i] = '\0';
    return dst;
}

int errno;

int abs(int x) { return x < 0 ? -x : x; }
long labs(long x) { return x < 0 ? -x : x; }

/* printf -- minimal implementation for test output */
static void put_char(char c) {
    semihost_call(SYS_WRITEC, &c);
}

static void put_str(const char *s) {
    while (*s) put_char(*s++);
}

static void put_uint(unsigned int v) {
    char buf[12];
    int i = 0;
    if (v == 0) { put_char('0'); return; }
    while (v) { buf[i++] = '0' + (v % 10); v /= 10; }
    while (i--) put_char(buf[i]);
}

static void put_hex_byte(uint8_t b) {
    const char *hex = "0123456789ABCDEF";
    put_char(hex[b >> 4]);
    put_char(hex[b & 0xF]);
}

static void put_int(int v) {
    if (v < 0) { put_char('-'); v = -v; }
    put_uint((unsigned int)v);
}

int printf(const char *fmt, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    int count = 0;
    while (*fmt) {
        if (*fmt == '%') {
            fmt++;
            if (*fmt == 's') {
                put_str(__builtin_va_arg(ap, const char *));
            } else if (*fmt == 'd') {
                put_int(__builtin_va_arg(ap, int));
            } else if (*fmt == 'u') {
                put_uint(__builtin_va_arg(ap, unsigned int));
            } else if (*fmt == 'z' && *(fmt+1) == 'u') {
                put_uint((unsigned int)__builtin_va_arg(ap, size_t));
                fmt++;
            } else if (*fmt == '0' && *(fmt+1) == '2' && *(fmt+2) == 'X') {
                put_hex_byte((uint8_t)__builtin_va_arg(ap, int));
                fmt += 2;
            } else if (*fmt == 'X' || *fmt == 'x') {
                unsigned int v = __builtin_va_arg(ap, unsigned int);
                if (v == 0) { put_char('0'); }
                else {
                    char buf[8]; int i = 0;
                    while (v) { buf[i++] = "0123456789ABCDEF"[v & 0xF]; v >>= 4; }
                    while (i--) put_char(buf[i]);
                }
            } else if (*fmt == '%') {
                put_char('%');
            } else if (*fmt == 'c') {
                put_char((char)__builtin_va_arg(ap, int));
            }
        } else {
            put_char(*fmt);
        }
        fmt++;
        count++;
    }
    __builtin_va_end(ap);
    return count;
}

int vprintf(const char *fmt, __builtin_va_list ap) {
    int count = 0;
    while (*fmt) {
        if (*fmt == '%') {
            fmt++;
            if (*fmt == 's') {
                put_str(__builtin_va_arg(ap, const char *));
            } else if (*fmt == 'd') {
                put_int(__builtin_va_arg(ap, int));
            } else if (*fmt == 'u') {
                put_uint(__builtin_va_arg(ap, unsigned int));
            } else if (*fmt == 'X' || *fmt == 'x') {
                unsigned int v = __builtin_va_arg(ap, unsigned int);
                if (v == 0) { put_char('0'); }
                else {
                    char buf[8]; int i = 0;
                    while (v) { buf[i++] = "0123456789ABCDEF"[v & 0xF]; v >>= 4; }
                    while (i--) put_char(buf[i]);
                }
            } else if (*fmt == 'c') {
                put_char((char)__builtin_va_arg(ap, int));
            } else if (*fmt == '%') {
                put_char('%');
            }
        } else {
            put_char(*fmt);
        }
        fmt++;
        count++;
    }
    return count;
}

int fflush(FILE *f) {
    (void)f;
    return 0;
}

int snprintf(char *buf, size_t size, const char *fmt, ...) {
    (void)fmt;
    if (size > 0) buf[0] = '\0';
    return 0;
}

int fprintf(FILE *f, const char *fmt, ...) {
    (void)f;
    /* Route to stdout via semihosting */
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    while (*fmt) {
        if (*fmt == '%') {
            fmt++;
            if (*fmt == 's') put_str(__builtin_va_arg(ap, const char *));
            else if (*fmt == 'd') put_int(__builtin_va_arg(ap, int));
        } else {
            put_char(*fmt);
        }
        fmt++;
    }
    __builtin_va_end(ap);
    return 0;
}

/* File I/O via semihosting */
static FILE _stdin_f = {0}, _stdout_f = {1}, _stderr_f = {2};
FILE *stdin = &_stdin_f;
FILE *stdout = &_stdout_f;
FILE *stderr = &_stderr_f;

FILE *fopen(const char *path, const char *mode) {
    int m = 0;
    if (mode[0] == 'r') m = 1; /* read binary */
    uint32_t args[3] = { (uint32_t)path, (uint32_t)m, (uint32_t)strlen(path) };
    int fd = semihost_call(SYS_OPEN, args);
    if (fd < 0) return NULL;
    static FILE files[4];
    static int next = 0;
    if (next >= 4) return NULL;
    files[next].fd = fd;
    return &files[next++];
}

size_t fread(void *buf, size_t elem, size_t count, FILE *f) {
    size_t total = elem * count;
    uint32_t args[3] = { (uint32_t)f->fd, (uint32_t)buf, (uint32_t)total };
    int not_read = semihost_call(SYS_READ, args);
    return (total - not_read) / elem;
}

int fclose(FILE *f) {
    uint32_t args[1] = { (uint32_t)f->fd };
    semihost_call(SYS_CLOSE, args);
    return 0;
}

/* RELIC needs these */
void *calloc(size_t nmemb, size_t size) {
    /* Simple bump allocator from end of BSS */
    extern uint32_t _end;
    static uint8_t *heap_ptr = NULL;
    if (!heap_ptr) heap_ptr = (uint8_t *)&_end;
    size_t total = nmemb * size;
    /* Align to 8 bytes */
    total = (total + 7) & ~7;
    void *p = heap_ptr;
    heap_ptr += total;
    memset(p, 0, total);
    return p;
}

void *malloc(size_t size) {
    return calloc(1, size);
}

void *realloc(void *ptr, size_t size) {
    void *new = malloc(size);
    if (ptr && new) memcpy(new, ptr, size);
    return new;
}

void free(void *ptr) {
    (void)ptr; /* bump allocator never frees */
}

void abort(void) {
    uint32_t args[2] = {0x20024, 0}; /* ADP_Stopped_InternalError */
    semihost_call(SYS_EXIT, args);
    while (1) {}
}

void exit(int code) {
    uint32_t args[2] = {0x20026, (uint32_t)code};
    semihost_call(SYS_EXIT, args);
    while (1) {}
}

int raise(int sig) { (void)sig; abort(); return 0; }

/* RELIC uses RAND=CALL; crypto_init.c registers a no-op rand callback, so the
 * verify path samples no randomness. The CALL backend's default rand_stub
 * (relic_rand_call.c) references these POSIX file ops but never runs once our
 * callback is registered — the stubs exist only to satisfy the linker. */
int open(const char *path, int flags) { (void)path; (void)flags; return -1; }
int read(int fd, void *buf, size_t count) { (void)fd; (void)buf; (void)count; return -1; }
int close(int fd) { (void)fd; return -1; }
