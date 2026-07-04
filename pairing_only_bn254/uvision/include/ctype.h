#ifndef _CTYPE_H
#define _CTYPE_H

static inline int isdigit(int c) { return c >= '0' && c <= '9'; }
static inline int isxdigit(int c) {
    return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static inline int isalpha(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static inline int toupper(int c) {
    return (c >= 'a' && c <= 'z') ? c - 32 : c;
}
static inline int tolower(int c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

#endif
