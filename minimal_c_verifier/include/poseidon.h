#ifndef POSEIDON_H
#define POSEIDON_H

#include <stdint.h>

#include "fr.h"

// Poseidon hash matching the arkworks PoseidonSponge used by the prover:
// BN254 Fr, width 3 (rate 2, capacity 1), x^5 S-box, 8 full + 56 partial rounds.
// Construction: state=[0, preimage, 0], permute once, output = state[1]
// (absorb one field element, squeeze one).

void poseidon_hash_fr(fr_t *out, const fr_t *preimage);

// Convenience byte wrapper: 32-byte big-endian preimage -> 32-byte big-endian hash.
void poseidon_hash_be(uint8_t out[32], const uint8_t in[32]);

#endif // POSEIDON_H
