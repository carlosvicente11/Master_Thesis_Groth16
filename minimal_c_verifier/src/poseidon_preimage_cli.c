// File-driven Poseidon-preimage verifier: everything comes from the
// Rust-exported artifacts at runtime, nothing is compiled in.
//
//   poseidon_preimage_cli <vk_raw.bin> <proof_raw.bin> <public_input.bin>
//
// Statement: "the prover knows x such that Poseidon(x) = h". The public
// input IS the hash h (32 B, BE); the preimage x stays secret with the
// prover, so — unlike the clear-signing CLI — there is nothing for the
// verifier to recompute. It checks the proof against the given h.
//
// vk_raw.bin layout (768 B, written by export_vk_raw):
//   IC[0..1] (2 x 64 B G1) || e(alpha,beta) (384 B GT)
//   || -gamma (128 B G2) || -delta (128 B G2)

#include <stdio.h>
#include <stdlib.h>

#include "groth16_verifier.h"

#define VK_RAW_LEN 768
#define PROOF_LEN  256
#define PI_LEN     32

static uint8_t *load_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    uint8_t *buf = malloc((size_t)size);
    if (buf && fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    *len = (size_t)size;
    return buf;
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len) printf("\n  ");
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr,
                "usage: %s <vk_raw.bin> <proof_raw.bin> <public_input.bin>\n",
                argv[0]);
        return 2;
    }

    size_t vk_len, proof_len, pi_len;
    uint8_t *vk_buf = load_file(argv[1], &vk_len);
    uint8_t *proof = load_file(argv[2], &proof_len);
    uint8_t *pi = load_file(argv[3], &pi_len);
    if (!vk_buf || !proof || !pi) return 2;
    if (vk_len != VK_RAW_LEN) {
        fprintf(stderr, "vk_raw.bin: expected %d bytes, got %zu\n", VK_RAW_LEN, vk_len);
        return 2;
    }
    if (proof_len != PROOF_LEN) {
        fprintf(stderr, "proof_raw.bin: expected %d bytes, got %zu\n", PROOF_LEN, proof_len);
        return 2;
    }
    if (pi_len != PI_LEN) {
        fprintf(stderr, "public_input.bin: expected %d bytes, got %zu\n", PI_LEN, pi_len);
        return 2;
    }

    if (groth16_init() != 0) {
        fprintf(stderr, "groth16_init failed\n");
        return 2;
    }

    const groth16_vk_t vk = {
        .ic = vk_buf,                       /* 2 x 64 B */
        .num_public_inputs = 1,
        .alpha_beta = vk_buf + 128,         /* 384 B */
        .neg_gamma = vk_buf + 128 + 384,    /* 128 B */
        .neg_delta = vk_buf + 128 + 384 + 128, /* 128 B */
    };

    int r = groth16_verify_vk(&vk, proof, PROOF_LEN, pi, PI_LEN);

    printf("=== Poseidon-Preimage Verification ===\n\n");
    print_hex("h = Poseidon(x), public input", pi, PI_LEN);
    printf("\nverification: %s\n",
           r == 1 ? "VALID (prover knows a preimage of h)"
                  : (r == 0 ? "INVALID" : "ERROR"));

    groth16_cleanup();
    return (r == 1) ? 0 : 1;
}
