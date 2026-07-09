#include <stdio.h>
#include <stdlib.h>

#include "pairing.h"
#include "test_vectors.h"

/* Standalone BN254 Groth16 multi-pairing benchmark.
 * Usage: multi_pairing_bench [iterations]   (default 100) */
int main(int argc, char **argv) {
    int iterations = 100;
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations < 1) iterations = 1;
    }

    if (pairing_init() != 0) {
        printf("FAIL: pairing_init\n");
        return 1;
    }

    printf("=== BN254 Groth16 Multi-Pairing ===\n");
    printf("e(A,B) * e(L,-gamma) * e(C,-delta) ?= e(alpha,beta)\n");
    printf("(shared Miller loop + single final exponentiation)\n\n");

    mp_bench_result_t r;
    int rc = run_multipairing_bench(TEST_PROOF, 256, TEST_PUBLIC_INPUT, 32,
                                    iterations, &r);
    if (rc != 0) {
        printf("FAIL: run_multipairing_bench (rc=%d)\n", rc);
        pairing_cleanup();
        return 1;
    }

    printf("Correctness: %s\n", r.valid ? "PASS (equals e(alpha,beta))"
                                        : "FAIL (mismatch)");
    printf("Iterations:  %d\n", r.iterations);
    printf("Total time:  %.6f s\n", r.total_seconds);
    printf("Per pairing: %.2f us\n", r.us_per_pairing);

    pairing_cleanup();
    return r.valid ? 0 : 1;
}
