#include <stdint.h>
#include <stdio.h>
#include "groth16_verifier.h"
#include "vk_constants.h"
#include "test_vectors.h"

/* Number of pairings to run. The driver script builds this binary twice with
 * different values and subtracts the instruction counts, which cancels the
 * fixed init+decode cost and yields the per-pairing figure. */
#ifndef PAIRING_ITERS
#define PAIRING_ITERS 1
#endif

/* SysTick registers (standard Cortex-M, same on real HW and QEMU) */
#define SYST_CSR  (*(volatile uint32_t *)0xE000E010)
#define SYST_RVR  (*(volatile uint32_t *)0xE000E014)
#define SYST_CVR  (*(volatile uint32_t *)0xE000E018)

#define SYSTICK_RELOAD 0x00FFFFFF  /* 24-bit max = 16777215 */

volatile uint32_t systick_overflow_count;

void SysTick_Handler(void) {
    systick_overflow_count++;
}

static void systick_init(void) {
    SYST_RVR = SYSTICK_RELOAD;
    SYST_CVR = 0;
    SYST_CSR = (1 << 2) | (1 << 1) | (1 << 0);
}

static void systick_reset(void) {
    SYST_CVR = 0;
    systick_overflow_count = 0;
}

static uint32_t systick_elapsed(void) {
    uint32_t cvr = SYST_CVR;
    uint32_t overflows = systick_overflow_count;
    uint32_t partial = SYSTICK_RELOAD - cvr;
    return overflows * (SYSTICK_RELOAD + 1) + partial;
}

int main(void) {
    if (groth16_init() != 0) {
        printf("FAIL: groth16_init\n");
        return 1;
    }

    /* --- Build the three pairs exactly as groth16_verify() does --- */
    ep_t A, C, L, ic0, ic1, tmp;
    ep2_t B, neg_gamma, neg_delta;
    bn_t scalar;
    fp12_t result;

    ep_null(A); ep_null(C); ep_null(L);
    ep_null(ic0); ep_null(ic1); ep_null(tmp);
    ep2_null(B); ep2_null(neg_gamma); ep2_null(neg_delta);
    bn_null(scalar); fp12_null(result);

    ep_new(A); ep_new(C); ep_new(L);
    ep_new(ic0); ep_new(ic1); ep_new(tmp);
    ep2_new(B); ep2_new(neg_gamma); ep2_new(neg_delta);
    bn_new(scalar); fp12_new(result);

    if (decode_g1(A, TEST_PROOF) != 0 ||
        decode_g2(B, TEST_PROOF + 64) != 0 ||
        decode_g1(C, TEST_PROOF + 192) != 0 ||
        decode_g2(neg_gamma, VK_NEG_GAMMA_G2) != 0 ||
        decode_g2(neg_delta, VK_NEG_DELTA_G2) != 0 ||
        decode_g1(ic0, VK_IC0_G1) != 0 ||
        decode_g1(ic1, VK_IC1_G1) != 0 ||
        decode_fr(scalar, TEST_PUBLIC_INPUT) != 0) {
        printf("FAIL: decode\n");
        return 1;
    }

    /* L = IC0 + scalar * IC1 */
    ep_mul(tmp, ic1, scalar);
    ep_add(L, ic0, tmp);
    ep_norm(L, L);

    ep_t p_arr[3];
    ep2_t q_arr[3];
    ep_null(p_arr[0]); ep_null(p_arr[1]); ep_null(p_arr[2]);
    ep2_null(q_arr[0]); ep2_null(q_arr[1]); ep2_null(q_arr[2]);
    ep_new(p_arr[0]); ep_new(p_arr[1]); ep_new(p_arr[2]);
    ep2_new(q_arr[0]); ep2_new(q_arr[1]); ep2_new(q_arr[2]);

    ep_copy(p_arr[0], A);
    ep_copy(p_arr[1], L);
    ep_copy(p_arr[2], C);
    ep2_copy(q_arr[0], B);
    ep2_copy(q_arr[1], neg_gamma);
    ep2_copy(q_arr[2], neg_delta);

    printf("=== Pairing-only Benchmark (pp_map_sim_k12, 3 pairs) ===\n");
    printf("PAIRING_ITERS: %d\n", PAIRING_ITERS);

    systick_init();

    for (int i = 0; i < PAIRING_ITERS; i++) {
        systick_reset();
        pp_map_sim_k12(result, p_arr, q_arr, 3);
        uint32_t t = systick_elapsed();
        printf("  iter %d: %u ticks\n", i, t);
    }

    ep_free(p_arr[0]); ep_free(p_arr[1]); ep_free(p_arr[2]);
    ep2_free(q_arr[0]); ep2_free(q_arr[1]); ep2_free(q_arr[2]);
    ep_free(A); ep_free(C); ep_free(L);
    ep_free(ic0); ep_free(ic1); ep_free(tmp);
    ep2_free(B); ep2_free(neg_gamma); ep2_free(neg_delta);
    bn_free(scalar); fp12_free(result);

    groth16_cleanup();
    return 0;
}
