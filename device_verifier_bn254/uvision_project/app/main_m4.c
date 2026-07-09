#include <stdint.h>
#include <stdio.h>

#include "pairing.h"
#include "vk_constants.h"
#include "test_vectors.h"

/* Bare-metal BN254 Groth16 multi-pairing benchmark (Cortex-M4).
 *
 * Same measurement as the host multi_pairing_bench: point setup (incl. the one
 * ep_mul that forms L) is untimed; the timed region is pp_map_sim_k12 alone
 * (3 pairs, shared Miller loop + single final exponentiation), checked against
 * the precomputed e(alpha,beta).
 *
 * Timing uses SysTick (standard Cortex-M, present on real HW, the Keil uVision
 * simulator, and QEMU). Cycle counts are only meaningful in the uVision
 * cycle-accurate simulator or on real silicon — QEMU SysTick is not
 * cycle-accurate and serves as a functional gate only.
 *
 * Results are also stored in volatile globals so they can be read from the
 * uVision watch window if semihosted printf is not routed anywhere. */

#ifndef PAIRING_ITERS
#define PAIRING_ITERS 3
#endif

/* SysTick registers */
#define SYST_CSR  (*(volatile uint32_t *)0xE000E010)
#define SYST_RVR  (*(volatile uint32_t *)0xE000E014)
#define SYST_CVR  (*(volatile uint32_t *)0xE000E018)

#define SYSTICK_RELOAD 0x00FFFFFF  /* 24-bit max */

volatile uint32_t systick_overflow_count;

/* Watch-window results */
volatile uint32_t g_valid;                     /* 1 = equals e(alpha,beta) */
volatile uint32_t g_iters = PAIRING_ITERS;
volatile uint32_t g_ticks[PAIRING_ITERS];      /* cycles per multi-pairing */
volatile uint32_t g_done;

void SysTick_Handler(void) {
    systick_overflow_count++;
}

static void systick_init(void) {
    SYST_RVR = SYSTICK_RELOAD;
    SYST_CVR = 0;
    SYST_CSR = (1 << 2) | (1 << 1) | (1 << 0);  /* core clock, IRQ, enable */
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
    if (pairing_init() != 0) {
        printf("FAIL: pairing_init\n");
        return 1;
    }

    ep_t A, C, L, ic0, ic1, tmp;
    ep2_t B, neg_gamma, neg_delta;
    bn_t scalar;
    fp12_t result, cached_ab;

    ep_null(A); ep_null(C); ep_null(L);
    ep_null(ic0); ep_null(ic1); ep_null(tmp);
    ep2_null(B); ep2_null(neg_gamma); ep2_null(neg_delta);
    bn_null(scalar); fp12_null(result); fp12_null(cached_ab);

    ep_new(A); ep_new(C); ep_new(L);
    ep_new(ic0); ep_new(ic1); ep_new(tmp);
    ep2_new(B); ep2_new(neg_gamma); ep2_new(neg_delta);
    bn_new(scalar); fp12_new(result); fp12_new(cached_ab);

    /* --- Point setup (untimed) --- */
    if (decode_g1(A, TEST_PROOF) != 0 ||
        decode_g2(B, TEST_PROOF + 64) != 0 ||
        decode_g1(C, TEST_PROOF + 192) != 0 ||
        decode_g2(neg_gamma, VK_NEG_GAMMA_G2) != 0 ||
        decode_g2(neg_delta, VK_NEG_DELTA_G2) != 0 ||
        decode_gt(cached_ab, VK_ALPHA_BETA_GT) != 0 ||
        decode_g1(ic0, VK_IC0_G1) != 0 ||
        decode_g1(ic1, VK_IC1_G1) != 0 ||
        decode_fr(scalar, TEST_PUBLIC_INPUT) != 0) {
        printf("FAIL: decode\n");
        return 1;
    }

    /* L = IC0 + pi * IC1 */
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

    printf("=== BN254 Groth16 Multi-Pairing (Cortex-M4) ===\n");
    printf("e(A,B) * e(L,-gamma) * e(C,-delta) ?= e(alpha,beta)\n");
    printf("PAIRING_ITERS: %d\n", PAIRING_ITERS);

    /* --- Warm-up + correctness check (untimed) --- */
    pp_map_sim_k12(result, p_arr, q_arr, 3);
    g_valid = (fp12_cmp(result, cached_ab) == RLC_EQ) ? 1 : 0;
    printf("Correctness: %s\n",
           g_valid ? "PASS (equals e(alpha,beta))" : "FAIL (mismatch)");

    /* --- Timed region: the multi-pairing alone --- */
    systick_init();
    for (int i = 0; i < PAIRING_ITERS; i++) {
        systick_reset();
        pp_map_sim_k12(result, p_arr, q_arr, 3);
        g_ticks[i] = systick_elapsed();
        printf("  iter %d: %u cycles\n", i, g_ticks[i]);
    }
    g_done = 1;

    ep_free(p_arr[0]); ep_free(p_arr[1]); ep_free(p_arr[2]);
    ep2_free(q_arr[0]); ep2_free(q_arr[1]); ep2_free(q_arr[2]);
    ep_free(A); ep_free(C); ep_free(L);
    ep_free(ic0); ep_free(ic1); ep_free(tmp);
    ep2_free(B); ep2_free(neg_gamma); ep2_free(neg_delta);
    bn_free(scalar); fp12_free(result); fp12_free(cached_ab);

    pairing_cleanup();
    return g_valid ? 0 : 1;
}
