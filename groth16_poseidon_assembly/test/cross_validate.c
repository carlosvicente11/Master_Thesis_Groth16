#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <relic.h>

#include "groth16_verifier.h"
#include "vk_constants.h"
#include "test_vectors.h"

static void put_hex_byte(uint8_t b) {
    const char hex[] = "0123456789abcdef";
    printf("%c%c", hex[b >> 4], hex[b & 0x0f]);
}

static void print_hex(const char *label, const uint8_t *buf, int len) {
    printf("%s = ", label);
    for (int i = 0; i < len; i++)
        put_hex_byte(buf[i]);
    printf("\n");
}

static void print_fp(const char *label, const fp_t a) {
    uint8_t buf[32];
    fp_write_bin(buf, 32, a);
    print_hex(label, buf, 32);
}

static void print_g1(const char *prefix, const ep_t p) {
    ep_t norm;
    ep_null(norm); ep_new(norm);
    ep_norm(norm, p);

    printf("%s.x = ", prefix);
    uint8_t buf[32];
    fp_write_bin(buf, 32, norm->x);
    for (int i = 0; i < 32; i++) put_hex_byte(buf[i]);
    printf("\n");

    printf("%s.y = ", prefix);
    fp_write_bin(buf, 32, norm->y);
    for (int i = 0; i < 32; i++) put_hex_byte(buf[i]);
    printf("\n");

    ep_free(norm);
}

static void print_g2(const char *prefix, const ep2_t p) {
    ep2_t norm;
    ep2_null(norm); ep2_new(norm);
    ep2_norm(norm, p);

    const char *suffixes[4] = { ".x.c0", ".x.c1", ".y.c0", ".y.c1" };
    fp_t *fields[4] = { &norm->x[0], &norm->x[1], &norm->y[0], &norm->y[1] };
    uint8_t buf[32];
    for (int i = 0; i < 4; i++) {
        printf("%s%s = ", prefix, suffixes[i]);
        fp_write_bin(buf, 32, *fields[i]);
        for (int j = 0; j < 32; j++) put_hex_byte(buf[j]);
        printf("\n");
    }

    ep2_free(norm);
}

static void print_fp12(const char *prefix, const fp12_t f) {
    const char *names[12] = {
        "c0.c0.c0", "c0.c0.c1",
        "c0.c1.c0", "c0.c1.c1",
        "c0.c2.c0", "c0.c2.c1",
        "c1.c0.c0", "c1.c0.c1",
        "c1.c1.c0", "c1.c1.c1",
        "c1.c2.c0", "c1.c2.c1",
    };
    int idx = 0;
    uint8_t buf[32];
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 2; k++) {
                printf("  %s = ", names[idx]);
                fp_write_bin(buf, 32, f[i][j][k]);
                for (int b = 0; b < 32; b++) put_hex_byte(buf[b]);
                printf("\n");
                idx++;
            }
        }
    }
}

int main(void) {
    if (groth16_init() != 0) {
        printf("FAIL: groth16_init\n");
        return 1;
    }

    printf("=== C Cross-Validation Dump (Basic Preimage) ===\n\n");

    /* Phase 1: Decode proof */
    printf("--- Phase 1: Decoded Proof ---\n");
    ep_t A, C;
    ep2_t B;
    ep_null(A); ep_null(C); ep2_null(B);
    ep_new(A); ep_new(C); ep2_new(B);

    decode_g1(A, TEST_PROOF);
    decode_g2(B, TEST_PROOF + 64);
    decode_g1(C, TEST_PROOF + 192);

    print_g1("A", A);
    print_g2("B", B);
    print_g1("C", C);

    /* Phase 2: VK points */
    printf("\n--- Phase 2: VK Points ---\n");
    ep_t ic0, ic1;
    ep_null(ic0); ep_null(ic1);
    ep_new(ic0); ep_new(ic1);
    decode_g1(ic0, VK_IC0_G1);
    decode_g1(ic1, VK_IC1_G1);
    print_g1("IC[0]", ic0);
    print_g1("IC[1]", ic1);

    ep2_t neg_gamma, neg_delta;
    ep2_null(neg_gamma); ep2_null(neg_delta);
    ep2_new(neg_gamma); ep2_new(neg_delta);
    decode_g2(neg_gamma, VK_NEG_GAMMA_G2);
    decode_g2(neg_delta, VK_NEG_DELTA_G2);
    print_g2("neg_gamma", neg_gamma);
    print_g2("neg_delta", neg_delta);

    fp12_t cached_ab;
    fp12_null(cached_ab); fp12_new(cached_ab);
    decode_gt(cached_ab, VK_ALPHA_BETA_GT);
    printf("\ne(alpha, beta) [precomputed]:\n");
    print_fp12("cached_ab", cached_ab);

    /* Phase 3: prepare_inputs */
    printf("\n--- Phase 3: prepare_inputs ---\n");
    print_hex("public_input[0]", TEST_PUBLIC_INPUT, 32);

    ep_t L, tmp;
    bn_t scalar;
    ep_null(L); ep_null(tmp); bn_null(scalar);
    ep_new(L); ep_new(tmp); bn_new(scalar);

    decode_fr(scalar, TEST_PUBLIC_INPUT);
    ep_mul(tmp, ic1, scalar);
    ep_add(L, ic0, tmp);
    ep_norm(L, L);
    print_g1("L", L);

    /* Phase 4: Multi-pairing */
    printf("\n--- Phase 4: Multi-pairing ---\n");
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

    printf("pairing result (after final exp):\n");
    print_fp12("result", result);

    /* Phase 5: Compare */
    printf("\n--- Phase 5: Compare ---\n");
    int cmp = (fp12_cmp(result, cached_ab) == RLC_EQ) ? 1 : 0;
    printf("pairing_result == e(alpha,beta): %s\n", cmp ? "true" : "false");

    int verify_result = groth16_verify(TEST_PROOF, 256, TEST_PUBLIC_INPUT, 32);
    printf("groth16_verify: %d\n", verify_result);

    /* Cleanup */
    ep_free(A); ep_free(C); ep2_free(B);
    ep_free(ic0); ep_free(ic1);
    ep2_free(neg_gamma); ep2_free(neg_delta);
    fp12_free(cached_ab);
    ep_free(L); ep_free(tmp); bn_free(scalar);
    for (int i = 0; i < 3; i++) {
        ep_free(p_arr[i]); ep2_free(q_arr[i]);
    }
    fp12_free(result);

    printf("\n=== END ===\n");
    groth16_cleanup();
    return 0;
}
