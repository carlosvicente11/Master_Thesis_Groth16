#include <stdint.h>
#include <stdio.h>

#include "pairing.h"
#include "vk_constants.h"
#include "test_vectors.h"

/* Bare-metal BN254 single-pairing micro-benchmark (Cortex-M4).
 *
 * The timed region is one pp_map_k12(e, A, B) — one Miller loop + one final
 * exponentiation. This isolates the cost of a single pairing so low-level
 * changes (e.g. Montgomery multiplication drop-in replacements in
 * low/easy/fp_{mulm,sqrm,rdcn}_low) can be measured without the Groth16
 * 3-pair sharing effects of multi_pairing_m4.
 *
 * Correctness gate: a single pairing has no precomputed expected value, so
 * bilinearity is checked instead: e([2]A, B) == e(A, B)^2, plus e(A,B) != 1.
 *
 * Timing uses SysTick, as in main_m4.c. QEMU is a functional gate only;
 * cycle counts are meaningful in the uVision simulator or on silicon. */

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
volatile uint32_t g_valid;                     /* 1 = bilinearity holds */
volatile uint32_t g_iters = PAIRING_ITERS;
volatile uint32_t g_ticks[PAIRING_ITERS];      /* cycles per single pairing */
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

    ep_t A, A2;
    ep2_t B;
    fp12_t e_ab, e_2ab, sq;

    ep_null(A); ep_null(A2); ep2_null(B);
    fp12_null(e_ab); fp12_null(e_2ab); fp12_null(sq);

    ep_new(A); ep_new(A2); ep2_new(B);
    fp12_new(e_ab); fp12_new(e_2ab); fp12_new(sq);

    /* --- Point setup (untimed): A, B from the test proof --- */
    if (decode_g1(A, TEST_PROOF) != 0 ||
        decode_g2(B, TEST_PROOF + 64) != 0) {
        printf("FAIL: decode\n");
        return 1;
    }
    ep_dbl(A2, A);
    ep_norm(A2, A2);

    printf("=== BN254 Single Pairing (Cortex-M4) ===\n");
    printf("e(A,B): 1 Miller loop + 1 final exponentiation\n");
    printf("PAIRING_ITERS: %d\n", PAIRING_ITERS);

    /* --- Warm-up + bilinearity check (untimed) --- */
    pp_map_k12(e_ab, A, B);
    pp_map_k12(e_2ab, A2, B);
    fp12_sqr(sq, e_ab);
    g_valid = (fp12_cmp(e_2ab, sq) == RLC_EQ &&
               fp12_cmp_dig(e_ab, 1) != RLC_EQ) ? 1 : 0;
    printf("Correctness: %s\n",
           g_valid ? "PASS (e([2]A,B) == e(A,B)^2, e(A,B) != 1)"
                   : "FAIL (bilinearity mismatch)");

    /* --- Timed region: one pairing alone --- */
    systick_init();
    for (int i = 0; i < PAIRING_ITERS; i++) {
        systick_reset();
        pp_map_k12(e_ab, A, B);
        g_ticks[i] = systick_elapsed();
        printf("  iter %d: %u cycles\n", i, g_ticks[i]);
    }
    g_done = 1;

    ep_free(A); ep_free(A2); ep2_free(B);
    fp12_free(e_ab); fp12_free(e_2ab); fp12_free(sq);

    pairing_cleanup();
    return g_valid ? 0 : 1;
}
