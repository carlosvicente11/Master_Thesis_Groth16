#include "pairing.h"

int decode_g1(ep_t p, const uint8_t buf[64]) {
    fp_read_bin(p->x, buf, 32);
    fp_read_bin(p->y, buf + 32, 32);
    fp_set_dig(p->z, 1);
    p->coord = BASIC;

    if (!ep_on_curve(p)) {
        return -1;
    }
    return 0;
}

int decode_g2(ep2_t p, const uint8_t buf[128]) {
    fp_read_bin(p->x[0], buf, 32);
    fp_read_bin(p->x[1], buf + 32, 32);
    fp_read_bin(p->y[0], buf + 64, 32);
    fp_read_bin(p->y[1], buf + 96, 32);
    fp2_set_dig(p->z, 1);
    p->coord = BASIC;

    if (!ep2_on_curve(p)) {
        return -1;
    }
    return 0;
}

int decode_fr(bn_t s, const uint8_t buf[32]) {
    bn_read_bin(s, buf, 32);
    return 0;
}

int decode_gt(fp12_t gt, const uint8_t buf[384]) {
    int offset = 0;
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 2; k++) {
                fp_read_bin(gt[i][j][k], buf + offset, 32);
                offset += 32;
            }
        }
    }
    return 0;
}
