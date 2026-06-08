#include <stdio.h>
#include <string.h>
#include "groth16_verifier.h"
#include "test_vectors.h"

static int failures = 0;

static void check(const char *name, int cond) {
    printf("  %s: %s\n", name, cond ? "YES" : "NO");
    if (!cond) failures++;
}

int main(void) {
    if (groth16_init() != 0) {
        printf("FAIL: groth16_init\n");
        return 1;
    }

    printf("=== Groth16 Verifier (ARM) ===\n");

    /* Valid proof */
    int result = groth16_verify(TEST_PROOF, 256, TEST_PUBLIC_INPUT, 32);
    check("valid proof accepted", result == 1);

    /* Tampered proof */
    uint8_t bad_proof[256];
    memcpy(bad_proof, TEST_PROOF, 256);
    bad_proof[10] ^= 0xFF;
    result = groth16_verify(bad_proof, 256, TEST_PUBLIC_INPUT, 32);
    check("tampered proof rejected", result == 0 || result == -1);

    /* Tampered public input */
    uint8_t bad_pi[32];
    memcpy(bad_pi, TEST_PUBLIC_INPUT, 32);
    bad_pi[15] ^= 0x01;
    result = groth16_verify(TEST_PROOF, 256, bad_pi, 32);
    check("tampered input rejected", result == 0);

    /* Wrong lengths */
    check("bad length rejected", groth16_verify(TEST_PROOF, 128, TEST_PUBLIC_INPUT, 32) == -1);

    printf("\n=== %s (%d failure%s) ===\n",
           failures == 0 ? "All tests passed" : "FAILURES",
           failures, failures == 1 ? "" : "s");

    groth16_cleanup();
    return failures;
}
