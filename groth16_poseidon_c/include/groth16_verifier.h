#ifndef GROTH16_VERIFIER_H
#define GROTH16_VERIFIER_H

#include <stddef.h>
#include <stdint.h>
#include <relic.h>

/* --- Init / Cleanup --- */

int  groth16_init(void);
void groth16_cleanup(void);

/* --- Point Decode --- */

int decode_g1(ep_t p, const uint8_t buf[64]);
int decode_g2(ep2_t p, const uint8_t buf[128]);
int decode_fr(bn_t s, const uint8_t buf[32]);
int decode_gt(fp12_t gt, const uint8_t buf[384]);

/* --- Verification (Step 4) --- */

int groth16_verify(
    const uint8_t *proof_buf,        /* 256 bytes: A(64) || B(128) || C(64) */
    size_t         proof_len,
    const uint8_t *public_input_buf, /* 32 bytes per public input */
    size_t         pi_len
);

#endif /* GROTH16_VERIFIER_H */
