#ifndef FR_H
#define FR_H

#include <stdint.h>

// Minimal arithmetic over the BN254 scalar field Fr (mod the group order r),
// used by the Poseidon hash. This is NOT the pairing's base field Fp (mod p);
// r and p are different primes. Self-contained: no RELIC dependency.
//
// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//   = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
//
// Elements are stored canonical (< r) as 4 little-endian 64-bit limbs.
// Representation is normal (non-Montgomery) form, so the canonical big-endian
// constants dumped from arkworks load directly.

typedef struct {
    uint64_t v[4];
} fr_t;

// Load a 32-byte big-endian integer, reduced mod r.
void fr_from_be(fr_t *out, const uint8_t in[32]);

// Store as a 32-byte big-endian integer (canonical, < r).
void fr_to_be(const fr_t *in, uint8_t out[32]);

void fr_set_u64(fr_t *out, uint64_t x);
void fr_set_zero(fr_t *out);

void fr_add(fr_t *out, const fr_t *a, const fr_t *b);
void fr_sub(fr_t *out, const fr_t *a, const fr_t *b);
void fr_mul(fr_t *out, const fr_t *a, const fr_t *b);

// out = a^5 (the Poseidon S-box).
void fr_pow5(fr_t *out, const fr_t *a);

int fr_eq(const fr_t *a, const fr_t *b);

#endif // FR_H
