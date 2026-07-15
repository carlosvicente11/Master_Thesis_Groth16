// File-driven clear-signing verifier: everything comes from the Rust-exported
// artifacts at runtime, nothing is compiled in.
//
//   clear_signing_cli <vk_raw.bin> <proof_raw.bin> <calldata.bin> <text.bin>
//
// The device-side protocol, end to end: hash the calldata and the display
// text on this side (never trusting the prover's public inputs), then verify
// the Groth16 proof against [h_c, h_t]. On VALID the text is the canonical
// rendering of the calldata and may be displayed.
//
// vk_raw.bin layout (832 B, written by export_vk_raw):
//   IC[0..2] (3 x 64 B G1) || e(alpha,beta) (384 B GT)
//   || -gamma (128 B G2) || -delta (128 B G2)

#include <stdio.h>
#include <stdlib.h>

#include "fr.h"
#include "groth16_verifier.h"
#include "poseidon.h"

#define VK_RAW_LEN 832
#define PROOF_LEN  256

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
    if (argc != 5) {
        fprintf(stderr,
                "usage: %s <vk_raw.bin> <proof_raw.bin> <calldata.bin> <text.bin>\n",
                argv[0]);
        return 2;
    }

    size_t vk_len, proof_len, calldata_len, text_len;
    uint8_t *vk_buf = load_file(argv[1], &vk_len);
    uint8_t *proof = load_file(argv[2], &proof_len);
    uint8_t *calldata = load_file(argv[3], &calldata_len);
    uint8_t *text = load_file(argv[4], &text_len);
    if (!vk_buf || !proof || !calldata || !text) return 2;
    if (vk_len != VK_RAW_LEN) {
        fprintf(stderr, "vk_raw.bin: expected %d bytes, got %zu\n", VK_RAW_LEN, vk_len);
        return 2;
    }
    if (proof_len != PROOF_LEN) {
        fprintf(stderr, "proof_raw.bin: expected %d bytes, got %zu\n", PROOF_LEN, proof_len);
        return 2;
    }

    if (groth16_init() != 0) {
        fprintf(stderr, "groth16_init failed\n");
        return 2;
    }

    const groth16_vk_t vk = {
        .ic = vk_buf,                       /* 3 x 64 B */
        .num_public_inputs = 2,
        .alpha_beta = vk_buf + 192,         /* 384 B */
        .neg_gamma = vk_buf + 192 + 384,    /* 128 B */
        .neg_delta = vk_buf + 192 + 384 + 128, /* 128 B */
    };

    /* The verifier's own view: hash C and T here, never trust the prover. */
    fr_t h;
    uint8_t pi[64];
    poseidon_hash_bytes(&h, calldata, calldata_len);
    fr_to_be(&h, pi);
    poseidon_hash_bytes(&h, text, text_len);
    fr_to_be(&h, pi + 32);

    int r = groth16_verify_vk(&vk, proof, PROOF_LEN, pi, sizeof(pi));

    printf("=== Clear-Signing Verification ===\n\n");
    print_hex("calldata", calldata, calldata_len);
    printf("text (%zu bytes):\n  \"%.*s\"\n", text_len, (int)text_len, text);
    print_hex("h_c = Poseidon(calldata)", pi, 32);
    print_hex("h_t = Poseidon(text)", pi + 32, 32);
    printf("\nverification: %s\n",
           r == 1 ? "VALID" : (r == 0 ? "INVALID" : "ERROR"));

    groth16_cleanup();
    return (r == 1) ? 0 : 1;
}
