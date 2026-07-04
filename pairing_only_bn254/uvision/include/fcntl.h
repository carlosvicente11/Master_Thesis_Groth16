#ifndef _FCNTL_H
#define _FCNTL_H

/* Bare-metal stub. RELIC's RAND=CALL backend (relic_rand_call.c) references
 * open()/O_RDONLY in its default rand_stub. We register our own no-op callback
 * (see crypto_init.c), so rand_stub never runs — these only satisfy the linker. */

#define O_RDONLY 0

int open(const char *path, int flags);

#endif
