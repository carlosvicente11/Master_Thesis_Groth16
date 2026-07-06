// Host-side profile of the clear-signing device flow (plan step 6):
// Poseidon(C) + Poseidon(T) on-chip, L = IC0 + h_c*IC1 + h_t*IC2 (2 ep_mul),
// 3-pair multi-pairing vs cached e(alpha,beta). Each phase is averaged over
// ITERS runs; host numbers are the reference for the uVision cycle counts.

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <relic.h>

#include "clear_signing_vectors.h"
#include "groth16_verifier.h"
#include "poseidon.h"
#include "vk_clear_signing.h"

#ifndef ITERS
#define ITERS 100
#endif

static double avg_ms(clock_t start, clock_t end, int iters) {
    return (double)(end - start) / CLOCKS_PER_SEC * 1000.0 / iters;
}

int main(void) {
    if (groth16_init() != 0) {
        printf("FAIL: groth16_init\n");
        return 1;
    }

    printf("=== Clear-Signing Verify Profile (host, %d iters/phase) ===\n\n",
           ITERS);

    fr_t h;
    uint8_t pi[64];
    clock_t t0, t1;
    double ms_hc, ms_ht, ms_decode, ms_prep, ms_pair, ms_total;

    /* Phase 1: Poseidon(C) — 68 B calldata */
    t0 = clock();
    for (int i = 0; i < ITERS; i++) {
        poseidon_hash_bytes(&h, CS_CALLDATA, sizeof(CS_CALLDATA));
    }
    t1 = clock();
    fr_to_be(&h, pi);
    ms_hc = avg_ms(t0, t1, ITERS);
    printf("1. Poseidon(C)  (68 B, 4 absorbs):  %10.3f ms\n", ms_hc);

    /* Phase 2: Poseidon(T) — 96 B text */
    t0 = clock();
    for (int i = 0; i < ITERS; i++) {
        poseidon_hash_bytes(&h, CS_TEXT, sizeof(CS_TEXT));
    }
    t1 = clock();
    fr_to_be(&h, pi + 32);
    ms_ht = avg_ms(t0, t1, ITERS);
    printf("2. Poseidon(T)  (96 B, 5 absorbs):  %10.3f ms\n", ms_ht);

    if (memcmp(pi, CS_EXPECTED_H_C, 32) != 0 ||
        memcmp(pi + 32, CS_EXPECTED_H_T, 32) != 0) {
        printf("FAIL: on-chip hashes do not match prover\n");
        return 1;
    }

    /* Phase 3: decode proof + VK */
    ep_t A, C, ic0, ic1, ic2, L, tmp;
    ep2_t B, neg_gamma, neg_delta;
    bn_t s1, s2;
    fp12_t result, cached_ab;

    ep_null(A); ep_null(C); ep_null(ic0); ep_null(ic1); ep_null(ic2);
    ep_null(L); ep_null(tmp);
    ep2_null(B); ep2_null(neg_gamma); ep2_null(neg_delta);
    bn_null(s1); bn_null(s2);
    fp12_null(result); fp12_null(cached_ab);

    ep_new(A); ep_new(C); ep_new(ic0); ep_new(ic1); ep_new(ic2);
    ep_new(L); ep_new(tmp);
    ep2_new(B); ep2_new(neg_gamma); ep2_new(neg_delta);
    bn_new(s1); bn_new(s2);
    fp12_new(result); fp12_new(cached_ab);

    t0 = clock();
    for (int i = 0; i < ITERS; i++) {
        decode_g1(A, CS_PROOF);
        decode_g2(B, CS_PROOF + 64);
        decode_g1(C, CS_PROOF + 192);
        decode_g2(neg_gamma, CS_VK_NEG_GAMMA_G2);
        decode_g2(neg_delta, CS_VK_NEG_DELTA_G2);
        decode_gt(cached_ab, CS_VK_ALPHA_BETA_GT);
        decode_g1(ic0, CS_VK_IC_G1);
        decode_g1(ic1, CS_VK_IC_G1 + 64);
        decode_g1(ic2, CS_VK_IC_G1 + 128);
        decode_fr(s1, pi);
        decode_fr(s2, pi + 32);
    }
    t1 = clock();
    ms_decode = avg_ms(t0, t1, ITERS);
    printf("3. Decode proof + VK:               %10.3f ms\n", ms_decode);

    /* Phase 4: prepare_inputs — L = IC0 + h_c*IC1 + h_t*IC2 (2 ep_mul) */
    t0 = clock();
    for (int i = 0; i < ITERS; i++) {
        ep_mul(tmp, ic1, s1);
        ep_add(L, ic0, tmp);
        ep_mul(tmp, ic2, s2);
        ep_add(L, L, tmp);
        ep_norm(L, L);
    }
    t1 = clock();
    ms_prep = avg_ms(t0, t1, ITERS);
    printf("4. prepare_inputs (2 ep_mul):       %10.3f ms\n", ms_prep);

    /* Phase 5: 3-pair multi-pairing */
    ep_t p_arr[3];
    ep2_t q_arr[3];
    for (int i = 0; i < 3; i++) {
        ep_null(p_arr[i]); ep2_null(q_arr[i]);
        ep_new(p_arr[i]); ep2_new(q_arr[i]);
    }
    ep_copy(p_arr[0], A);
    ep_copy(p_arr[1], L);
    ep_copy(p_arr[2], C);
    ep2_copy(q_arr[0], B);
    ep2_copy(q_arr[1], neg_gamma);
    ep2_copy(q_arr[2], neg_delta);

    t0 = clock();
    for (int i = 0; i < ITERS; i++) {
        pp_map_sim_k12(result, p_arr, q_arr, 3);
    }
    t1 = clock();
    ms_pair = avg_ms(t0, t1, ITERS);
    printf("5. Multi-pairing (3 pairs):         %10.3f ms\n", ms_pair);

    int valid = (fp12_cmp(result, cached_ab) == RLC_EQ) ? 1 : 0;

    /* Phase 6: full flow end-to-end via the public API */
    static const groth16_vk_t vk = {
        .ic = CS_VK_IC_G1,
        .num_public_inputs = CLEAR_SIGNING_NUM_PUBLIC_INPUTS,
        .alpha_beta = CS_VK_ALPHA_BETA_GT,
        .neg_gamma = CS_VK_NEG_GAMMA_G2,
        .neg_delta = CS_VK_NEG_DELTA_G2,
    };
    int r = 1;
    t0 = clock();
    for (int i = 0; i < ITERS; i++) {
        poseidon_hash_bytes(&h, CS_CALLDATA, sizeof(CS_CALLDATA));
        fr_to_be(&h, pi);
        poseidon_hash_bytes(&h, CS_TEXT, sizeof(CS_TEXT));
        fr_to_be(&h, pi + 32);
        r &= (groth16_verify_vk(&vk, CS_PROOF, 256, pi, sizeof(pi)) == 1);
    }
    t1 = clock();
    ms_total = avg_ms(t0, t1, ITERS);
    printf("   ---------------------------------------------\n");
    printf("   Sum of phases 1-5:               %10.3f ms\n",
           ms_hc + ms_ht + ms_decode + ms_prep + ms_pair);
    printf("6. Full verify (public API, E2E):   %10.3f ms\n", ms_total);
    printf("\n   Result: %s\n",
           (valid && r) ? "VALID" : "INVALID");

    for (int i = 0; i < 3; i++) {
        ep_free(p_arr[i]); ep2_free(q_arr[i]);
    }
    ep_free(A); ep_free(C); ep_free(ic0); ep_free(ic1); ep_free(ic2);
    ep_free(L); ep_free(tmp);
    ep2_free(B); ep2_free(neg_gamma); ep2_free(neg_delta);
    bn_free(s1); bn_free(s2);
    fp12_free(result); fp12_free(cached_ab);

    groth16_cleanup();
    return (valid && r) ? 0 : 1;
}
