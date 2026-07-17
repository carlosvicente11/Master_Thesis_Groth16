#include <stdio.h>
#include <string.h>
#include "groth16_verifier.h"

static int failures = 0;

static void check(const char *name, int cond) {
    printf("  %s: %s\n", name, cond ? "YES" : "NO");
    if (!cond) failures++;
}

static int load_file(const char *name, uint8_t *buf, size_t expected) {
    /* Try from build dir (../test/) and from project root (test/). */
    char path[256];
    snprintf(path, sizeof(path), "../test/%s", name);
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(path, sizeof(path), "test/%s", name);
        f = fopen(path, "rb");
    }
    if (!f) {
        printf("  FAIL: %s not found (run from minimal_c_verifier/, its test/ or build/ dir)\n",
               name);
        failures++;
        return -1;
    }
    size_t n = fread(buf, 1, expected, f);
    fclose(f);
    if (n != expected) {
        printf("  FAIL: %s is %zu bytes, expected %zu\n", name, n, expected);
        failures++;
        return -1;
    }
    return 0;
}

static void test_valid_proof(void) {
    printf("\n--- Test: valid proof ---\n");

    uint8_t proof[256], pi[32];
    if (load_file("proof_raw.bin", proof, 256) != 0) return;
    if (load_file("public_input_raw.bin", pi, 32) != 0) return;

    int result = groth16_verify(proof, 256, pi, 32);
    check("valid proof accepted", result == 1);
}

static void test_tampered_proof(void) {
    printf("\n--- Test: tampered proof ---\n");

    uint8_t proof[256], pi[32];
    if (load_file("proof_raw.bin", proof, 256) != 0) return;
    if (load_file("public_input_raw.bin", pi, 32) != 0) return;

    /* Flip a byte in the proof.A x-coordinate. */
    proof[10] ^= 0xFF;
    int result = groth16_verify(proof, 256, pi, 32);
    check("tampered proof.A rejected", result == 0 || result == -1);
}

static void test_tampered_public_input(void) {
    printf("\n--- Test: tampered public input ---\n");

    uint8_t proof[256], pi[32];
    if (load_file("proof_raw.bin", proof, 256) != 0) return;
    if (load_file("public_input_raw.bin", pi, 32) != 0) return;

    /* Flip a byte in the public input. */
    pi[15] ^= 0x01;
    int result = groth16_verify(proof, 256, pi, 32);
    check("tampered public input rejected", result == 0);
}

static void test_wrong_lengths(void) {
    printf("\n--- Test: wrong input lengths ---\n");

    uint8_t proof[256] = {0}, pi[32] = {0};

    check("proof too short rejected", groth16_verify(proof, 128, pi, 32) == -1);
    check("pi too short rejected", groth16_verify(proof, 256, pi, 16) == -1);
    check("both wrong rejected", groth16_verify(proof, 0, pi, 0) == -1);
}

static void test_zero_public_input(void) {
    printf("\n--- Test: zero public input ---\n");

    uint8_t proof[256], pi[32];
    if (load_file("proof_raw.bin", proof, 256) != 0) return;

    /* Zero public input — L = IC[0] (no IC[1] contribution).
     * This should produce a different L, so verification fails. */
    memset(pi, 0, 32);
    int result = groth16_verify(proof, 256, pi, 32);
    check("zero public input rejected", result == 0);
}

int main(void) {
    if (groth16_init() != 0) {
        printf("FAIL: groth16_init\n");
        return 1;
    }

    printf("=== Groth16 Verifier Tests ===\n");

    test_valid_proof();
    test_tampered_proof();
    test_tampered_public_input();
    test_wrong_lengths();
    test_zero_public_input();

    printf("\n=== %s (%d failure%s) ===\n",
           failures == 0 ? "All tests passed" : "FAILURES",
           failures, failures == 1 ? "" : "s");

    groth16_cleanup();
    return failures > 0 ? 1 : 0;
}
