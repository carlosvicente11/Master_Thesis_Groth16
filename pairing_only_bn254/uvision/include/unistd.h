#ifndef _UNISTD_H
#define _UNISTD_H

#include <stddef.h>

/* Bare-metal stub. RELIC's RAND=CALL backend (relic_rand_call.c) references
 * read()/close() in its default rand_stub. We register our own no-op callback
 * (see crypto_init.c), so rand_stub never runs — these only satisfy the linker. */

int read(int fd, void *buf, size_t count);
int close(int fd);

#endif
