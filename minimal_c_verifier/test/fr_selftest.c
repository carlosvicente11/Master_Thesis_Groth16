#include "fr.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int cond, const char *name) {
    printf("  %-40s %s\n", name, cond ? "OK" : "FAIL");
    if (!cond) failures++;
}

// r - 1, big-endian.
static const uint8_t R_MINUS_1_BE[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45,
    0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9,
    0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
};

int main(void) {
    printf("=== Fr self-test ===\n");

    fr_t zero, one, two, three, six;
    fr_set_zero(&zero);
    fr_set_u64(&one, 1);
    fr_set_u64(&two, 2);
    fr_set_u64(&three, 3);
    fr_set_u64(&six, 6);

    // (r-1) + 1 == 0
    fr_t rm1, t;
    fr_from_be(&rm1, R_MINUS_1_BE);
    fr_add(&t, &rm1, &one);
    check(fr_eq(&t, &zero), "(r-1) + 1 == 0");

    // 1 - 2 == r-1
    fr_sub(&t, &one, &two);
    check(fr_eq(&t, &rm1), "1 - 2 == r-1");

    // 2 * 3 == 6
    fr_mul(&t, &two, &three);
    check(fr_eq(&t, &six), "2 * 3 == 6");

    // 7^5 == 16807
    fr_t seven, exp16807, p5;
    fr_set_u64(&seven, 7);
    fr_set_u64(&exp16807, 16807);
    fr_pow5(&p5, &seven);
    check(fr_eq(&p5, &exp16807), "7^5 == 16807");

    // (r-1)*(r-1) == 1   (i.e. (-1)^2 == 1)
    fr_mul(&t, &rm1, &rm1);
    check(fr_eq(&t, &one), "(r-1)^2 == 1");

    // a * 1 == a  (use a non-trivial value)
    fr_t a;
    fr_from_be(&a, R_MINUS_1_BE);
    fr_set_u64(&a, 0); // overwrite then build something nontrivial
    uint8_t some_be[32] = {0};
    some_be[31] = 0x07;
    some_be[30] = 0xde;
    some_be[0] = 0x12;
    fr_from_be(&a, some_be);
    fr_mul(&t, &a, &one);
    check(fr_eq(&t, &a), "a * 1 == a");

    // round-trip: from_be -> to_be is identity for a canonical value
    uint8_t rt[32];
    fr_to_be(&a, rt);
    check(memcmp(rt, some_be, 32) == 0, "from_be/to_be round-trip");

    printf("\n%s (%d failure(s))\n", failures ? "FAILED" : "All Fr tests passed",
           failures);
    return failures ? 1 : 0;
}
