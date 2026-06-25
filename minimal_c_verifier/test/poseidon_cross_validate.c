#include "fr.h"
#include "poseidon.h"

#include <stdio.h>
#include <string.h>

// Expected outputs from the arkworks prover (dump_poseidon_params.rs):
// poseidon_hash(absorb 1, squeeze 1), 32-byte big-endian.
typedef struct {
    uint64_t input;
    const char *expected_hex;
} vector_t;

static const vector_t VECTORS[] = {
    {0, "221b3ba83d3ba29c81faf792c0456758b3a085bcdb02254e0ab72fb22a4904f7"},
    {1, "2af2ed1c9b2652bd81834197d0cee2fffa753302ebecf13c7984da368b272389"},
    {2, "0556e50c057a08733a6ea0d06c9625048380b7f192cba1c8ae87d7f359588fda"},
    {42, "105db015c5ad74a7bc2683cd441025c20ead72d269034cc9989d67d8903d8643"},
    {12345, "1ed0e1845ff27a8d23cd6167fca00c2acc564aaa0680c2863dfe704a239d78f4"},
};

static void hex_to_bytes(const char *hex, uint8_t out[32]) {
    for (int i = 0; i < 32; i++) {
        unsigned int b;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (uint8_t)b;
    }
}

static void print_hex(const uint8_t b[32]) {
    for (int i = 0; i < 32; i++) printf("%02x", b[i]);
}

int main(void) {
    printf("=== Poseidon cross-validation vs arkworks prover ===\n");
    int failures = 0;
    int n = sizeof(VECTORS) / sizeof(VECTORS[0]);

    for (int k = 0; k < n; k++) {
        fr_t x, h;
        fr_set_u64(&x, VECTORS[k].input);
        poseidon_hash_fr(&h, &x);

        uint8_t got[32], want[32];
        fr_to_be(&h, got);
        hex_to_bytes(VECTORS[k].expected_hex, want);

        int ok = memcmp(got, want, 32) == 0;
        printf("H(%llu): %s\n", (unsigned long long)VECTORS[k].input,
               ok ? "MATCH" : "MISMATCH");
        if (!ok) {
            failures++;
            printf("  got  = ");
            print_hex(got);
            printf("\n  want = ");
            print_hex(want);
            printf("\n");
        }
    }

    printf("\n%s (%d failure(s))\n",
           failures ? "CROSS-VALIDATION FAILED" : "All Poseidon vectors match",
           failures);
    return failures ? 1 : 0;
}
