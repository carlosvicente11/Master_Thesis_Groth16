#include "poseidon.h"

#include <string.h>

#include "poseidon_constants.h"

static fr_t ARK[POSEIDON_TOTAL_ROUNDS][POSEIDON_WIDTH];
static fr_t MDS[POSEIDON_WIDTH][POSEIDON_WIDTH];
static int initialized = 0;

static void poseidon_init(void) {
    if (initialized) return;
    for (int r = 0; r < POSEIDON_TOTAL_ROUNDS; r++) {
        for (int c = 0; c < POSEIDON_WIDTH; c++) {
            fr_from_be(&ARK[r][c], POSEIDON_ARK[r][c]);
        }
    }
    for (int i = 0; i < POSEIDON_WIDTH; i++) {
        for (int j = 0; j < POSEIDON_WIDTH; j++) {
            fr_from_be(&MDS[i][j], POSEIDON_MDS[i][j]);
        }
    }
    initialized = 1;
}

static void permute(fr_t state[POSEIDON_WIDTH]) {
    const int half_full = POSEIDON_FULL_ROUNDS / 2; // 4
    const int partial_end = half_full + POSEIDON_PARTIAL_ROUNDS; // 60

    for (int round = 0; round < POSEIDON_TOTAL_ROUNDS; round++) {
        // ARK: add round constants.
        for (int i = 0; i < POSEIDON_WIDTH; i++) {
            fr_add(&state[i], &state[i], &ARK[round][i]);
        }

        // S-box: full rounds apply x^5 to all elements; partial rounds only to state[0].
        int is_full = (round < half_full) || (round >= partial_end);
        if (is_full) {
            for (int i = 0; i < POSEIDON_WIDTH; i++) {
                fr_pow5(&state[i], &state[i]);
            }
        } else {
            fr_pow5(&state[0], &state[0]);
        }

        // MDS: new_state[i] = sum_j MDS[i][j] * state[j].
        fr_t next[POSEIDON_WIDTH];
        for (int i = 0; i < POSEIDON_WIDTH; i++) {
            fr_t acc;
            fr_set_zero(&acc);
            for (int j = 0; j < POSEIDON_WIDTH; j++) {
                fr_t prod;
                fr_mul(&prod, &MDS[i][j], &state[j]);
                fr_add(&acc, &acc, &prod);
            }
            next[i] = acc;
        }
        memcpy(state, next, sizeof(next));
    }
}

void poseidon_hash_fr(fr_t *out, const fr_t *preimage) {
    poseidon_init();

    fr_t state[POSEIDON_WIDTH];
    fr_set_zero(&state[0]); // capacity
    state[1] = *preimage;   // absorb into first rate slot
    fr_set_zero(&state[2]);

    permute(state);

    *out = state[1]; // squeeze first rate slot
}

void poseidon_hash_be(uint8_t out[32], const uint8_t in[32]) {
    fr_t x, h;
    fr_from_be(&x, in);
    poseidon_hash_fr(&h, &x);
    fr_to_be(&h, out);
}

// arkworks duplex absorb: permute lazily, only when the rate is full AND
// another element arrives; the final permute happens at squeeze time.
static void sponge_absorb(fr_t state[POSEIDON_WIDTH], int *idx, const fr_t *e) {
    if (*idx == POSEIDON_WIDTH - 1) { // rate = width - capacity = 2
        permute(state);
        *idx = 0;
    }
    fr_add(&state[1 + *idx], &state[1 + *idx], e);
    (*idx)++;
}

void poseidon_hash_bytes(fr_t *out, const uint8_t *data, size_t len) {
    poseidon_init();

    fr_t state[POSEIDON_WIDTH];
    for (int i = 0; i < POSEIDON_WIDTH; i++) fr_set_zero(&state[i]);

    int idx = 0;
    fr_t e;

    // pack(data) = [Fr(len)] ++ 31-byte big-endian chunks.
    fr_set_u64(&e, (uint64_t)len);
    sponge_absorb(state, &idx, &e);

    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > 31) n = 31;
        uint8_t buf[32] = {0};
        memcpy(buf + 32 - n, data + off, n); // right-aligned = BE integer value
        fr_from_be(&e, buf);
        sponge_absorb(state, &idx, &e);
        off += n;
    }

    permute(state); // squeeze
    *out = state[1];
}
