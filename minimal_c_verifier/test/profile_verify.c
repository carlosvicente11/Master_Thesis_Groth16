#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <relic.h>

#include "groth16_verifier.h"
#include "vk_constants.h"
#include "test_vectors.h"

static double elapsed_ms(clock_t start, clock_t end) {
    return (double)(end - start) / CLOCKS_PER_SEC * 1000.0;
}

int main(void) {
    if (groth16_init() != 0) {
        printf("FAIL: groth16_init\n");
        return 1;
    }

    printf("=== Groth16 Verification Profile ===\n\n");

    clock_t t_total_start = clock();

    /* Phase 1: Decode proof */
    clock_t t0 = clock();

    ep_t A, C;
    ep2_t B;
    ep_null(A); ep_null(C); ep2_null(B);
    ep_new(A); ep_new(C); ep2_new(B);

    decode_g1(A, TEST_PROOF);
    decode_g2(B, TEST_PROOF + 64);
    decode_g1(C, TEST_PROOF + 192);

    clock_t t1 = clock();
    printf("1. Decode proof (A, B, C):       %8.3f ms\n", elapsed_ms(t0, t1));

    /* Phase 2: Decode VK */
    t0 = clock();

    ep2_t neg_gamma, neg_delta;
    fp12_t cached_ab;
    ep2_null(neg_gamma); ep2_null(neg_delta);
    fp12_null(cached_ab);
    ep2_new(neg_gamma); ep2_new(neg_delta);
    fp12_new(cached_ab);

    decode_g2(neg_gamma, VK_NEG_GAMMA_G2);
    decode_g2(neg_delta, VK_NEG_DELTA_G2);
    decode_gt(cached_ab, VK_ALPHA_BETA_GT);

    t1 = clock();
    printf("2. Decode VK (gamma, delta, GT): %8.3f ms\n", elapsed_ms(t0, t1));

    /* Phase 3: prepare_inputs */
    t0 = clock();

    ep_t ic0, ic1, L, tmp;
    bn_t scalar;
    ep_null(ic0); ep_null(ic1); ep_null(L); ep_null(tmp);
    bn_null(scalar);
    ep_new(ic0); ep_new(ic1); ep_new(L); ep_new(tmp);
    bn_new(scalar);

    decode_g1(ic0, VK_IC0_G1);
    decode_g1(ic1, VK_IC1_G1);
    decode_fr(scalar, TEST_PUBLIC_INPUT);
    ep_mul(tmp, ic1, scalar);
    ep_add(L, ic0, tmp);
    ep_norm(L, L);

    t1 = clock();
    printf("3. prepare_inputs (L):           %8.3f ms\n", elapsed_ms(t0, t1));

    /* Phase 4: Multi-pairing */
    t0 = clock();

    ep_t p_arr[3];
    ep2_t q_arr[3];
    fp12_t result;
    for (int i = 0; i < 3; i++) {
        ep_null(p_arr[i]); ep2_null(q_arr[i]);
        ep_new(p_arr[i]); ep2_new(q_arr[i]);
    }
    fp12_null(result); fp12_new(result);

    ep_copy(p_arr[0], A);
    ep_copy(p_arr[1], L);
    ep_copy(p_arr[2], C);
    ep2_copy(q_arr[0], B);
    ep2_copy(q_arr[1], neg_gamma);
    ep2_copy(q_arr[2], neg_delta);

    pp_map_sim_k12(result, p_arr, q_arr, 3);

    t1 = clock();
    printf("4. Multi-pairing (3 pairs):      %8.3f ms\n", elapsed_ms(t0, t1));

    /* Phase 5: Compare */
    t0 = clock();

    int cmp = (fp12_cmp(result, cached_ab) == RLC_EQ) ? 1 : 0;

    t1 = clock();
    printf("5. Compare (fp12_cmp):           %8.3f ms\n", elapsed_ms(t0, t1));

    clock_t t_total_end = clock();

    printf("   ----------------------------------------\n");
    printf("   Total:                        %8.3f ms\n", elapsed_ms(t_total_start, t_total_end));
    printf("\n   Result: %s\n", cmp ? "VALID" : "INVALID");

    /* Cleanup */
    ep_free(A); ep_free(C); ep2_free(B);
    ep_free(ic0); ep_free(ic1); ep_free(L); ep_free(tmp);
    bn_free(scalar);
    ep2_free(neg_gamma); ep2_free(neg_delta);
    fp12_free(cached_ab);
    for (int i = 0; i < 3; i++) {
        ep_free(p_arr[i]); ep2_free(q_arr[i]);
    }
    fp12_free(result);

    groth16_cleanup();
    return 0;
}
