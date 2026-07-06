// Clear-signing E2E (plan step 5): the chip receives (C, T, proof), computes
// h_c = Poseidon(pack(C)) and h_t = Poseidon(pack(T)) itself, and verifies the
// Groth16 proof with public inputs [h_c, h_t]. On PASS it may display T: the
// proof guarantees T is the canonical rendering of C.

#include <stdio.h>
#include <string.h>

#include "clear_signing_vectors.h"
#include "groth16_verifier.h"
#include "poseidon.h"
#include "vk_clear_signing.h"

static const groth16_vk_t CS_VK = {
    .ic = CS_VK_IC_G1,
    .num_public_inputs = CLEAR_SIGNING_NUM_PUBLIC_INPUTS,
    .alpha_beta = CS_VK_ALPHA_BETA_GT,
    .neg_gamma = CS_VK_NEG_GAMMA_G2,
    .neg_delta = CS_VK_NEG_DELTA_G2,
};

/* The full device-side check: hash C and T on-chip, then verify. */
static int clear_signing_verify(const uint8_t *calldata, size_t calldata_len,
                                const uint8_t *text, size_t text_len,
                                const uint8_t proof[256]) {
    fr_t h;
    uint8_t pi[64];
    poseidon_hash_bytes(&h, calldata, calldata_len);
    fr_to_be(&h, pi);
    poseidon_hash_bytes(&h, text, text_len);
    fr_to_be(&h, pi + 32);
    return groth16_verify_vk(&CS_VK, proof, 256, pi, sizeof(pi));
}

int main(void) {
    if (groth16_init() != 0) {
        printf("FAIL: groth16_init\n");
        return 1;
    }

    printf("=== Groth16 Clear-Signing Verifier (two-hash, ERC-20 transfer) ===\n\n");
    int failures = 0;

    /* Sanity: on-chip hashes must equal the prover's public inputs. */
    fr_t h;
    uint8_t got[32];
    poseidon_hash_bytes(&h, CS_CALLDATA, sizeof(CS_CALLDATA));
    fr_to_be(&h, got);
    int hc_ok = memcmp(got, CS_EXPECTED_H_C, 32) == 0;
    poseidon_hash_bytes(&h, CS_TEXT, sizeof(CS_TEXT));
    fr_to_be(&h, got);
    int ht_ok = memcmp(got, CS_EXPECTED_H_T, 32) == 0;
    printf("on-chip h_c matches prover: %s\n", hc_ok ? "YES" : "NO");
    printf("on-chip h_t matches prover: %s\n", ht_ok ? "YES" : "NO");
    failures += !hc_ok + !ht_ok;

    /* E2E: genuine (C, T, proof) must verify. */
    int r = clear_signing_verify(CS_CALLDATA, sizeof(CS_CALLDATA),
                                 CS_TEXT, sizeof(CS_TEXT), CS_PROOF);
    printf("genuine (C, T, proof):      %s\n", r == 1 ? "VALID" : "INVALID/ERROR");
    if (r == 1) {
        printf("  device displays: \"%.*s\"\n", (int)sizeof(CS_TEXT), CS_TEXT);
    }
    failures += (r != 1);

    /* Tampered T: displayed amount lies -> h_t changes -> proof must fail. */
    uint8_t bad_text[sizeof(CS_TEXT)];
    memcpy(bad_text, CS_TEXT, sizeof(CS_TEXT));
    bad_text[14] ^= 0x01; /* last integer digit of the amount */
    r = clear_signing_verify(CS_CALLDATA, sizeof(CS_CALLDATA),
                             bad_text, sizeof(bad_text), CS_PROOF);
    printf("tampered T (amount digit):  %s\n", r == 0 ? "REJECTED" : "NOT REJECTED");
    failures += (r != 0);

    /* Tampered C: different transfer under the same text -> must fail. */
    uint8_t bad_calldata[sizeof(CS_CALLDATA)];
    memcpy(bad_calldata, CS_CALLDATA, sizeof(CS_CALLDATA));
    bad_calldata[67] ^= 0x01; /* amount low byte */
    r = clear_signing_verify(bad_calldata, sizeof(bad_calldata),
                             CS_TEXT, sizeof(CS_TEXT), CS_PROOF);
    printf("tampered C (amount byte):   %s\n", r == 0 ? "REJECTED" : "NOT REJECTED");
    failures += (r != 0);

    groth16_cleanup();
    printf("\n%s (%d failure(s))\n",
           failures == 0 ? "Clear-signing E2E PASS" : "Clear-signing E2E FAIL", failures);
    return failures;
}
