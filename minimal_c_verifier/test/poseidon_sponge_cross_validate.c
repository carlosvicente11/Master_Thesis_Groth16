// Cross-validates the C byte-string Poseidon sponge (poseidon_hash_bytes)
// against vectors produced by the arkworks prover side:
//   groth16_poseidon_rust: cargo run --bin dump_sponge_vectors
// GATE (CLEAR_SIGNING_TWO_HASH_PLAN.md step 2): identical digests Rust <-> C.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "poseidon.h"

typedef struct {
    const char *label;
    const uint8_t *data;
    size_t len;
    const char *expected_hex;
} vector_t;

static int hex_to_bytes(uint8_t *out, size_t out_len, const char *hex) {
    if (strlen(hex) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

int main(void) {
    uint8_t seq[63];
    for (size_t i = 0; i < sizeof(seq); i++) seq[i] = (uint8_t)(i + 1);

    // ERC-20 transfer(address,uint256): a9059cbb + to(0x11 x20) + amount 12500000.
    uint8_t calldata[68];
    memset(calldata, 0, sizeof(calldata));
    calldata[0] = 0xa9; calldata[1] = 0x05; calldata[2] = 0x9c; calldata[3] = 0xbb;
    memset(calldata + 16, 0x11, 20);
    calldata[64] = 0x00; calldata[65] = 0xbe; calldata[66] = 0xbc; calldata[67] = 0x20;

    const char *text =
        "Send 12.500000 USDC to 0x1111111111111111111111111111111111111111";

    const vector_t VECTORS[] = {
        {"empty (len 0)", seq, 0,
         "221b3ba83d3ba29c81faf792c0456758b3a085bcdb02254e0ab72fb22a4904f7"},
        {"single byte 0xab (len 1)", (const uint8_t *)"\xab", 1,
         "1408f715b3d94d113eeef0ca8e9e12dd859c24bfcfebd6bcd6f040cb6233ec71"},
        {"0x01..0x1f (len 31, one chunk)", seq, 31,
         "2964dd9a0441be42dc5f2ae16cf24b39fcd07be2f8fec22029935a778030f634"},
        {"0x01..0x20 (len 32, two chunks)", seq, 32,
         "0dbecac93d0936e10d3250c5c6893a7f0182f8213caf162b27ae2af6eaa617f7"},
        {"0x01..0x3e (len 62, two chunks)", seq, 62,
         "1da2903930af5daabf6cc36ba34e170421a44feaa1d96128a0e450edc6dd63d4"},
        {"0x01..0x3f (len 63, three chunks)", seq, 63,
         "05ab1bf17d01985b6e1f70bb4dcca5206505893244810f986debad4c817c80d6"},
        {"ERC-20 transfer calldata (len 68)", calldata, 68,
         "2a6393f66d58092b2929a90a9f61796d454bfd8b9a4dc2376e7a0b86d876306c"},
        {"sample text (len 65)", (const uint8_t *)text, 65,
         "24baa2cdaa9302dbdf6b4db7e815c992b3ae3b7a0c101bbb65561952de903483"},
    };
    const size_t NUM = sizeof(VECTORS) / sizeof(VECTORS[0]);

    if (strlen(text) != 65) {
        printf("FATAL: sample text length %zu != 65\n", strlen(text));
        return 1;
    }

    int failures = 0;
    for (size_t v = 0; v < NUM; v++) {
        uint8_t expected[32];
        if (hex_to_bytes(expected, 32, VECTORS[v].expected_hex) != 0) {
            printf("FATAL: bad expected hex for '%s'\n", VECTORS[v].label);
            return 1;
        }

        fr_t h;
        poseidon_hash_bytes(&h, VECTORS[v].data, VECTORS[v].len);
        uint8_t got[32];
        fr_to_be(&h, got);

        int ok = memcmp(got, expected, 32) == 0;
        printf("H(%s): %s\n", VECTORS[v].label, ok ? "MATCH" : "MISMATCH");
        if (!ok) {
            printf("  expected: %s\n  got     : ", VECTORS[v].expected_hex);
            for (int i = 0; i < 32; i++) printf("%02x", got[i]);
            printf("\n");
            failures++;
        }
    }

    printf("\n%s: %d failure(s) out of %zu vectors\n",
           failures == 0 ? "All sponge vectors match" : "SPONGE CROSS-VALIDATION FAILED",
           failures, NUM);
    return failures;
}
