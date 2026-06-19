#include "groth16_verifier.h"

#if RAND == CALL
/* The verify path samples no randomness, but RAND=CALL leaves rand_bytes
 * dispatching through a callback. Register a no-op so any stray rand use never
 * reaches the backend's /dev/urandom stub (which can't exist on bare metal). */
static void noop_rand(uint8_t *buf, size_t size, void *args) {
    (void)buf;
    (void)size;
    (void)args;
}
#endif

int groth16_init(void) {
    if (core_init() != RLC_OK) {
        return -1;
    }
#if RAND == CALL
    rand_seed(noop_rand, NULL);
#endif
    ep_param_set(BN_P254E);
    ep2_curve_set_twist(RLC_EP_DTYPE);
    return 0;
}

void groth16_cleanup(void) {
    core_clean();
}
