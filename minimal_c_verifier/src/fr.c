#include "fr.h"

#include <string.h>

// r as little-endian 64-bit limbs (limb[0] = least significant).
// r = 0x30644e72e131a029 b85045b68181585d 2833e84879b97091 43e1f593f0000001
static const uint64_t R_MOD[4] = {
    0x43e1f593f0000001ULL,
    0x2833e84879b97091ULL,
    0xb85045b68181585dULL,
    0x30644e72e131a029ULL,
};

// Returns -1, 0, +1 for a <, ==, > b (4-limb little-endian).
static int cmp4(const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 3; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// out = a - b (assumes a >= b), 4-limb little-endian.
static void sub4(uint64_t out[4], const uint64_t a[4], const uint64_t b[4]) {
    unsigned __int128 borrow = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 t = (unsigned __int128)a[i] - b[i] - borrow;
        out[i] = (uint64_t)t;
        borrow = (t >> 64) & 1; // 1 if it wrapped
    }
}

void fr_set_zero(fr_t *out) { memset(out->v, 0, sizeof(out->v)); }

void fr_set_u64(fr_t *out, uint64_t x) {
    out->v[0] = x;
    out->v[1] = out->v[2] = out->v[3] = 0;
}

void fr_from_be(fr_t *out, const uint8_t in[32]) {
    // Big-endian bytes -> little-endian limbs.
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | in[i * 8 + j];
        }
        out->v[3 - i] = limb;
    }
    // Reduce: any 256-bit value is < 4r (r ~ 2^254), so at most 3 subtractions.
    while (cmp4(out->v, R_MOD) >= 0) {
        sub4(out->v, out->v, R_MOD);
    }
}

void fr_to_be(const fr_t *in, uint8_t out[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t limb = in->v[3 - i];
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = (uint8_t)(limb >> (56 - 8 * j));
        }
    }
}

int fr_eq(const fr_t *a, const fr_t *b) { return cmp4(a->v, b->v) == 0; }

void fr_add(fr_t *out, const fr_t *a, const fr_t *b) {
    uint64_t t[4];
    unsigned __int128 carry = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 s = (unsigned __int128)a->v[i] + b->v[i] + carry;
        t[i] = (uint64_t)s;
        carry = s >> 64;
    }
    // a, b < r < 2^254, so a + b < 2^255: no carry out of 4 limbs; one subtract suffices.
    if (carry || cmp4(t, R_MOD) >= 0) {
        sub4(t, t, R_MOD);
    }
    memcpy(out->v, t, sizeof(t));
}

void fr_sub(fr_t *out, const fr_t *a, const fr_t *b) {
    uint64_t t[4];
    if (cmp4(a->v, b->v) >= 0) {
        sub4(t, a->v, b->v);
    } else {
        // a - b + r
        uint64_t apr[4];
        unsigned __int128 carry = 0;
        for (int i = 0; i < 4; i++) {
            unsigned __int128 s = (unsigned __int128)a->v[i] + R_MOD[i] + carry;
            apr[i] = (uint64_t)s;
            carry = s >> 64;
        }
        sub4(t, apr, b->v);
    }
    memcpy(out->v, t, sizeof(t));
}

void fr_mul(fr_t *out, const fr_t *a, const fr_t *b) {
    // Schoolbook 4x4 -> 8-limb product.
    uint64_t p[8] = {0};
    for (int i = 0; i < 4; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            unsigned __int128 t =
                (unsigned __int128)a->v[i] * b->v[j] + p[i + j] + carry;
            p[i + j] = (uint64_t)t;
            carry = t >> 64;
        }
        p[i + 4] += (uint64_t)carry;
    }

    // Reduce the 512-bit product mod r by binary long division.
    // r < 2^254, so the running remainder stays < 2^255 and fits in 4 limbs.
    uint64_t rem[4] = {0};
    for (int bit = 511; bit >= 0; bit--) {
        // rem <<= 1
        uint64_t carry = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t newcarry = rem[i] >> 63;
            rem[i] = (rem[i] << 1) | carry;
            carry = newcarry;
        }
        // bring down bit `bit` of the product
        rem[0] |= (p[bit >> 6] >> (bit & 63)) & 1ULL;
        // conditional subtract
        if (cmp4(rem, R_MOD) >= 0) {
            sub4(rem, rem, R_MOD);
        }
    }
    memcpy(out->v, rem, sizeof(rem));
}

void fr_pow5(fr_t *out, const fr_t *a) {
    fr_t t2, t4;
    fr_mul(&t2, a, a);   // a^2
    fr_mul(&t4, &t2, &t2); // a^4
    fr_mul(out, &t4, a);  // a^5
}
