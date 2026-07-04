#ifndef POSEIDON_H
#define POSEIDON_H

#include <stddef.h>
#include <stdint.h>

#include "fr.h"

// Poseidon hash matching the arkworks PoseidonSponge used by the prover:
// BN254 Fr, width 3 (rate 2, capacity 1), x^5 S-box, 8 full + 56 partial rounds.
// Construction: state=[0, preimage, 0], permute once, output = state[1]
// (absorb one field element, squeeze one).

void poseidon_hash_fr(fr_t *out, const fr_t *preimage);

// Convenience byte wrapper: 32-byte big-endian preimage -> 32-byte big-endian hash.
void poseidon_hash_be(uint8_t out[32], const uint8_t in[32]);

// Byte-string sponge hash (two-hash clear-signing convention, must match the
// Rust pack::poseidon_hash_bytes exactly):
//   pack(data) = [Fr(len)] ++ one Fr per 31-byte chunk (big-endian integer),
//   then arkworks-style rate-2 duplex absorb (+= into state[1..3], permute
//   when the rate is full and more elements arrive), final permute at squeeze,
//   digest = state[1].
void poseidon_hash_bytes(fr_t *out, const uint8_t *data, size_t len);

#endif // POSEIDON_H
