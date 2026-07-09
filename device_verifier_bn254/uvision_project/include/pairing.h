#ifndef PAIRING_H
#define PAIRING_H

#include <stddef.h>
#include <stdint.h>
#include <relic.h>

/* --- Init / Cleanup --- */

int  pairing_init(void);
void pairing_cleanup(void);

/* --- Point decode --- */

int decode_g1(ep_t p, const uint8_t buf[64]);
int decode_g2(ep2_t p, const uint8_t buf[128]);
int decode_fr(bn_t s, const uint8_t buf[32]);
int decode_gt(fp12_t gt, const uint8_t buf[384]);

/* --- BN254 Groth16 multi-pairing benchmark ---
 *
 * Evaluates the three-pairing product with a shared Miller loop and a single
 * final exponentiation:
 *
 *     e(A, B) * e(L, -gamma) * e(C, -delta)  ?=  e(alpha, beta)
 *
 * A, B, C come from the proof; -gamma, -delta and the precomputed e(alpha,beta)
 * come from the verifying key; L = IC0 + pi*IC1. All point setup (including the
 * single ep_mul that forms L) happens outside the timed region, so the reported
 * timing measures pp_map_sim_k12 alone. */

typedef struct {
    int    valid;           /* 1 if the multi-pairing equals e(alpha,beta) */
    int    iterations;
    double total_seconds;   /* wall time for all iterations of the pairing */
    double us_per_pairing;  /* microseconds per multi-pairing evaluation */
} mp_bench_result_t;

int run_multipairing_bench(
    const uint8_t *proof_buf,        /* 256 bytes: A(64) || B(128) || C(64) */
    size_t         proof_len,
    const uint8_t *public_input_buf, /* 32 bytes */
    size_t         pi_len,
    int            iterations,
    mp_bench_result_t *out
);

#endif /* PAIRING_H */
