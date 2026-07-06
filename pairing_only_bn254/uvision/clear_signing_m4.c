#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pairing.h"
#include "fr.h"
#include "poseidon.h"
#include "vk_clear_signing.h"
#include "clear_signing_vectors.h"

/* Bare-metal clear-signing verify benchmark (Cortex-M4), plan step 6.
 *
 * The full device flow of CLEAR_SIGNING_TWO_HASH_PLAN.md section 2, each phase
 * timed separately with SysTick:
 *   1. h_c = Poseidon(pack(C))                  (68 B calldata, 4 absorbs)
 *   2. h_t = Poseidon(pack(T))                  (96 B text, 5 absorbs)
 *   3. L = IC0 + h_c*IC1 + h_t*IC2              (2 ep_mul)
 *   4. e(A,B) * e(L,-gamma) * e(C,-delta)       (3-pair multi-pairing)
 * Point/VK decode is untimed setup, as in main_m4.c (negligible on host).
 *
 * The simulator is deterministic and the M4 has no data cache, so each phase
 * is timed once; a single untimed warm-up hash runs first so poseidon_init's
 * ARK/MDS conversion is not charged to phase 1.
 *
 * Cycle counts are meaningful in the Keil uVision cycle-accurate simulator or
 * on silicon; QEMU is a functional gate only. Results also land in volatile
 * globals for the uVision watch window. */

/* SysTick registers */
#define SYST_CSR  (*(volatile uint32_t *)0xE000E010)
#define SYST_RVR  (*(volatile uint32_t *)0xE000E014)
#define SYST_CVR  (*(volatile uint32_t *)0xE000E018)

#define SYSTICK_RELOAD 0x00FFFFFF  /* 24-bit max */

volatile uint32_t systick_overflow_count;

/* Watch-window results */
volatile uint32_t g_hashes_ok;   /* 1 = on-chip h_c/h_t match the prover */
volatile uint32_t g_valid;       /* 1 = pairing product equals e(alpha,beta) */
volatile uint64_t g_cycles_hc;
volatile uint64_t g_cycles_ht;
volatile uint64_t g_cycles_prep;
volatile uint64_t g_cycles_pair;
volatile uint64_t g_cycles_total;
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

static uint64_t systick_elapsed(void) {
    uint32_t cvr = SYST_CVR;
    uint32_t overflows = systick_overflow_count;
    uint32_t partial = SYSTICK_RELOAD - cvr;
    return (uint64_t)overflows * (SYSTICK_RELOAD + 1) + partial;
}

/* The minimal printf has no %llu: format u64 into a decimal string. */
static const char *u64_dec(uint64_t v) {
    static char buf[21];
    char *p = buf + sizeof(buf) - 1;
    *p = '\0';
    do {
        *--p = '0' + (char)(v % 10);
        v /= 10;
    } while (v);
    return p;
}

int main(void) {
    if (pairing_init() != 0) {
        printf("FAIL: pairing_init\n");
        return 1;
    }

    printf("=== BN254 Clear-Signing Verify (Cortex-M4) ===\n");

    fr_t h;
    uint8_t pi[64];

    /* Warm-up (untimed): triggers poseidon_init's ARK/MDS conversion. */
    poseidon_hash_bytes(&h, CS_CALLDATA, sizeof(CS_CALLDATA));

    systick_init();

    /* --- Phase 1: h_c = Poseidon(pack(C)) --- */
    systick_reset();
    poseidon_hash_bytes(&h, CS_CALLDATA, sizeof(CS_CALLDATA));
    g_cycles_hc = systick_elapsed();
    fr_to_be(&h, pi);

    /* --- Phase 2: h_t = Poseidon(pack(T)) --- */
    systick_reset();
    poseidon_hash_bytes(&h, CS_TEXT, sizeof(CS_TEXT));
    g_cycles_ht = systick_elapsed();
    fr_to_be(&h, pi + 32);

    g_hashes_ok = (memcmp(pi, CS_EXPECTED_H_C, 32) == 0 &&
                   memcmp(pi + 32, CS_EXPECTED_H_T, 32) == 0);
    printf("On-chip h_c/h_t match prover: %s\n", g_hashes_ok ? "YES" : "NO");
    printf("  Poseidon(C) 68 B: %s cycles\n", u64_dec(g_cycles_hc));
    printf("  Poseidon(T) 96 B: %s cycles\n", u64_dec(g_cycles_ht));

    /* --- Point/VK decode (untimed setup) --- */
    ep_t A, C, L, ic0, ic1, ic2, tmp;
    ep2_t B, neg_gamma, neg_delta;
    bn_t s1, s2;
    fp12_t result, cached_ab;

    ep_null(A); ep_null(C); ep_null(L);
    ep_null(ic0); ep_null(ic1); ep_null(ic2); ep_null(tmp);
    ep2_null(B); ep2_null(neg_gamma); ep2_null(neg_delta);
    bn_null(s1); bn_null(s2);
    fp12_null(result); fp12_null(cached_ab);

    ep_new(A); ep_new(C); ep_new(L);
    ep_new(ic0); ep_new(ic1); ep_new(ic2); ep_new(tmp);
    ep2_new(B); ep2_new(neg_gamma); ep2_new(neg_delta);
    bn_new(s1); bn_new(s2);
    fp12_new(result); fp12_new(cached_ab);

    if (decode_g1(A, CS_PROOF) != 0 ||
        decode_g2(B, CS_PROOF + 64) != 0 ||
        decode_g1(C, CS_PROOF + 192) != 0 ||
        decode_g2(neg_gamma, CS_VK_NEG_GAMMA_G2) != 0 ||
        decode_g2(neg_delta, CS_VK_NEG_DELTA_G2) != 0 ||
        decode_gt(cached_ab, CS_VK_ALPHA_BETA_GT) != 0 ||
        decode_g1(ic0, CS_VK_IC_G1) != 0 ||
        decode_g1(ic1, CS_VK_IC_G1 + 64) != 0 ||
        decode_g1(ic2, CS_VK_IC_G1 + 128) != 0 ||
        decode_fr(s1, pi) != 0 ||
        decode_fr(s2, pi + 32) != 0) {
        printf("FAIL: decode\n");
        return 1;
    }

    /* --- Phase 3: L = IC0 + h_c*IC1 + h_t*IC2 --- */
    systick_reset();
    ep_mul(tmp, ic1, s1);
    ep_add(L, ic0, tmp);
    ep_mul(tmp, ic2, s2);
    ep_add(L, L, tmp);
    ep_norm(L, L);
    g_cycles_prep = systick_elapsed();
    printf("  prepare_inputs (2 ep_mul): %s cycles\n", u64_dec(g_cycles_prep));

    /* --- Phase 4: 3-pair multi-pairing --- */
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

    systick_reset();
    pp_map_sim_k12(result, p_arr, q_arr, 3);
    g_cycles_pair = systick_elapsed();
    printf("  multi-pairing (3 pairs): %s cycles\n", u64_dec(g_cycles_pair));

    g_valid = (fp12_cmp(result, cached_ab) == RLC_EQ) ? 1 : 0;
    g_cycles_total = g_cycles_hc + g_cycles_ht + g_cycles_prep + g_cycles_pair;
    printf("  total verify: %s cycles\n", u64_dec(g_cycles_total));
    printf("Proof: %s\n", g_valid ? "VALID (equals e(alpha,beta))" : "INVALID");
    g_done = 1;

    ep_free(p_arr[0]); ep_free(p_arr[1]); ep_free(p_arr[2]);
    ep2_free(q_arr[0]); ep2_free(q_arr[1]); ep2_free(q_arr[2]);
    ep_free(A); ep_free(C); ep_free(L);
    ep_free(ic0); ep_free(ic1); ep_free(ic2); ep_free(tmp);
    ep2_free(B); ep2_free(neg_gamma); ep2_free(neg_delta);
    bn_free(s1); bn_free(s2);
    fp12_free(result); fp12_free(cached_ab);

    pairing_cleanup();
    return (g_hashes_ok && g_valid) ? 0 : 1;
}
