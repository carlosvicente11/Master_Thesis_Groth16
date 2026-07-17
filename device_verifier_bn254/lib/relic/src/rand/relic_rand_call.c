/*
 * RAND == CALL backend: randomness comes from a user-registered callback.
 * Restored for the bare-metal (Keil uVision / Cortex-M4) build, where UDEV's
 * /dev/urandom does not exist. The pairing verify path is deterministic and
 * never calls rand_bytes; registering no callback is fine, and any accidental
 * use throws ERR_NO_RAND instead of silently returning weak randomness.
 */

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_rand.h"
#include "relic_err.h"

#if RAND == CALL

void rand_bytes(uint8_t *buf, size_t size) {
	ctx_t *ctx = core_get();

	if (ctx->rand_call == NULL) {
		RLC_THROW(ERR_NO_RAND);
		return;
	}
	ctx->rand_call(buf, size, ctx->rand_args);
}

void rand_seed(void (*callback)(uint8_t *, size_t, void *), void *args) {
	ctx_t *ctx = core_get();

	ctx->rand_call = callback;
	ctx->rand_args = args;
	ctx->seeded = (callback != NULL);
}

#endif
