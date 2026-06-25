#include <stdio.h>
#include <string.h>
#include "groth16_verifier.h"
#include "test_vectors.h"

int main(void) {
    if (groth16_init() != 0) {
        printf("FAIL: groth16_init\n");
        return 1;
    }

    printf("=== Groth16 Poseidon Verifier ===\n\n");

    int result = groth16_verify(TEST_PROOF, 256, TEST_PUBLIC_INPUT, 32);

    if (result == 1) {
        printf("Verification: VALID\n");
    } else if (result == 0) {
        printf("Verification: INVALID\n");
    } else {
        printf("Verification: ERROR\n");
    }

    groth16_cleanup();
    return (result == 1) ? 0 : 1;
}
