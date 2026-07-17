/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2019 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of exponentiation in cyclotomic subgroups of extensions
 * defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_conv_cyc(fp2_t c, const fp2_t a) {
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		/* t = a^{-1}. */
		fp2_inv(t, a);
		/* c = a^p. */
		fp2_inv_cyc(c, a);
		/* c = a^(p - 1). */
		fp2_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}

int fp2_test_cyc(const fp2_t a) {
	fp2_t t;
	int result = 0;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);
		fp2_inv_cyc(t, a);
		fp2_mul(t, t, a);
		result = ((fp2_cmp_dig(t, 1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}

	return result;
}

void fp2_exp_cyc(fp2_t c, const fp2_t a, const bn_t b) {
	fp2_t r, s, t[1 << (RLC_WIDTH - 2)];
	int8_t naf[RLC_FP_BITS + 1], *k;
	size_t l;

	if (bn_is_zero(b)) {
		return fp2_set_dig(c, 1);
	}

	if (bn_bits(b) <= RLC_DIG) {
		fp2_exp_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			fp2_inv_cyc(c, c);
		}
		return;
	}

	fp2_null(r);
	fp2_null(s);

	RLC_TRY {
		fp2_new(r);
		fp2_new(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp2_null(t[i]);
			fp2_new(t[i]);
		}

#if RLC_WIDTH > 2
		fp2_sqr(t[0], a);
		fp2_mul(t[1], t[0], a);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_mul(t[i], t[i - 1], t[0]);
		}
#endif
		fp2_copy(t[0], a);

		l = RLC_FP_BITS + 1;
		fp2_set_dig(r, 1);
		bn_rec_naf(naf, &l, b, RLC_WIDTH);

		k = naf + l - 1;
		for (int i = l - 1; i >= 0; i--, k--) {
			fp2_sqr(r, r);

			if (*k > 0) {
				fp2_mul(r, r, t[*k / 2]);
			}
			if (*k < 0) {
				fp2_inv_cyc(s, t[-*k / 2]);
				fp2_mul(r, r, s);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp2_inv_cyc(c, r);
		} else {
			fp2_copy(c, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(r);
		fp2_free(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_free(t[i]);
		}
	}
}

void fp2_exp_cyc_sim(fp2_t e, const fp2_t a, const bn_t b, const fp2_t c,
		const bn_t d) {
	int n0, n1;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *_k, *_m;
	fp2_t r, t0[1 << (RLC_WIDTH - 2)];
	fp2_t s, t1[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	if (bn_is_zero(b)) {
		return fp2_exp_cyc(e, c, d);
	}

	if (bn_is_zero(d)) {
		return fp2_exp_cyc(e, a, b);
	}

	fp2_null(r);
	fp2_null(s);

	RLC_TRY {
		fp2_new(r);
		fp2_new(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp2_null(t0[i]);
			fp2_null(t1[i]);
			fp2_new(t0[i]);
			fp2_new(t1[i]);
		}

#if RLC_WIDTH > 2
		fp2_sqr(t0[0], a);
		fp2_mul(t0[1], t0[0], a);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_mul(t0[i], t0[i - 1], t0[0]);
		}

		fp2_sqr(t1[0], c);
		fp2_mul(t1[1], t1[0], c);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_mul(t1[i], t1[i - 1], t1[0]);
		}
#endif
		fp2_copy(t0[0], a);
		fp2_copy(t1[0], c);

		l0 = l1 = RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, b, RLC_WIDTH);
		bn_rec_naf(naf1, &l1, d, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		if (bn_sign(b) == RLC_NEG) {
			for (size_t i = 0; i < l0; i++) {
				naf0[i] = -naf0[i];
			}
		}
		if (bn_sign(d) == RLC_NEG) {
			for (size_t i = 0; i < l1; i++) {
				naf1[i] = -naf1[i];
			}
		}

		_k = naf0 + l - 1;
		_m = naf1 + l - 1;

		fp2_set_dig(r, 1);
		for (int i = l - 1; i >= 0; i--, _k--, _m--) {
			fp2_sqr(r, r);

			n0 = *_k;
			n1 = *_m;

			if (n0 > 0) {
				fp2_mul(r, r, t0[n0 / 2]);
			}
			if (n0 < 0) {
				fp2_inv_cyc(s, t0[-n0 / 2]);
				fp2_mul(r, r, s);
			}
			if (n1 > 0) {
				fp2_mul(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				fp2_inv_cyc(s, t1[-n1 / 2]);
				fp2_mul(r, r, s);
			}
		}

		fp2_copy(e, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(r);
		fp2_free(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_free(t0[i]);
			fp2_free(t1[i]);
		}
	}
}





void fp12_conv_cyc(fp12_t c, const fp12_t a) {
	fp12_t t;

	fp12_null(t);

	RLC_TRY {
		fp12_new(t);

		/* First, compute c = a^(p^6 - 1). */
		/* t = a^{-1}. */
		fp12_inv(t, a);
		/* c = a^(p^6). */
		fp12_inv_cyc(c, a);
		/* c = a^(p^6 - 1). */
		fp12_mul(c, c, t);

		/* Second, compute c^(p^2 + 1). */
		/* t = c^(p^2). */
		fp12_frb(t, c, 2);

		/* c = c^(p^2 + 1). */
		fp12_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free(t);
	}
}

int fp12_test_cyc(const fp12_t a) {
	fp12_t t0, t1;
	int result = 0;

	fp12_null(t0);
	fp12_null(t1);

	RLC_TRY {
		fp12_new(t0);
		fp12_new(t1);

		/* Check if a^(p^4 - p^2 + 1) == 1. */
		fp12_frb(t0, a, 4);
		fp12_mul(t0, t0, a);
		fp12_frb(t1, a, 2);

		result = ((fp12_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free(t0);
		fp12_free(t1);
	}

	return result;
}

void fp12_back_cyc(fp12_t c, const fp12_t a) {
	fp2_t t0, t1, t2;

	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);

		int f = fp2_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp2_copy(t2, a[0][1]);
		fp2_copy_sec(t2, a[1][2], f);
		/* t0 = g4^2. */
		fp2_mul(t0, a[0][1], t2);
		fp2_dbl(t2, t0);
		fp2_copy_sec(t0, t2, f);
		/* t1 = 3 * g4^2 - 2 * g3. */
		fp2_sub(t1, t0, a[0][2]);
		fp2_dbl(t1, t1);
		fp2_add(t1, t1, t0);
		/* t0 = E * g5^2 + t1. */
		fp2_sqr(t2, a[1][2]);
		fp2_mul_nor(t0, t2);
		fp2_add(t0, t0, t1);
		/* t1 = (4 * g2). */
		fp2_dbl(t1, a[1][0]);
		fp2_dbl(t1, t1);
		fp2_copy_sec(t1, a[0][2], f);
		/* If unity, decompress to unity as well. */
		f = fp12_cmp_dig(a, 1) == RLC_EQ;
		fp2_set_dig(t2, 1);
		fp2_copy_sec(t1, t2, f);

		/* t1 = 1/g3 or 1/(4*g2), depending on the above. */
		fp2_inv(t1, t1);
		/* c_1 = g1. */
		fp2_mul(c[1][1], t0, t1);

		/* t1 = g3 * g4. */
		fp2_mul(t1, a[0][2], a[0][1]);
		/* t2 = 2 * g1^2 - 3 * g3 * g4. */
		fp2_sqr(t2, c[1][1]);
		fp2_sub(t2, t2, t1);
		fp2_dbl(t2, t2);
		fp2_sub(t2, t2, t1);
		/* t1 = g2 * g5. */
		fp2_mul(t1, a[1][0], a[1][2]);
		/* c_0 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
		fp2_add(t2, t2, t1);
		fp2_mul_nor(c[0][0], t2);
		fp_add_dig(c[0][0][0], c[0][0][0], 1);

		fp2_copy(c[0][1], a[0][1]);
		fp2_copy(c[0][2], a[0][2]);
		fp2_copy(c[1][0], a[1][0]);
		fp2_copy(c[1][2], a[1][2]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t0);
		fp2_free(t1);
		fp2_free(t2);
	}
}

void fp12_back_cyc_sim(fp12_t c[], const fp12_t a[], int n) {
    fp2_t *t = RLC_ALLOCA(fp2_t, n * 3);
    fp2_t *t0 = t + 0 * n, *t1 = t + 1 * n, *t2 = t + 2 * n;

	if (n == 0) {
		RLC_FREE(t);
		return;
	}

	RLC_TRY {
		if (t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (int i = 0; i < n; i++) {
			fp2_null(t0[i]);
			fp2_null(t1[i]);
			fp2_null(t2[i]);
			fp2_new(t0[i]);
			fp2_new(t1[i]);
			fp2_new(t2[i]);
		}

		for (int i = 0; i < n; i++) {
			int f = fp2_is_zero(a[i][1][0]);
			/* If f, t0 = 2 * g4 * g5, t1 = g3. */
			fp2_copy(t2[i], a[i][0][1]);
			fp2_copy_sec(t2[i], a[i][1][2], f);
			/* t0 = g4^2. */
			fp2_mul(t0[i], a[i][0][1], t2[i]);
			fp2_dbl(t2[i], t0[i]);
			fp2_copy_sec(t0[i], t2[i], f);
			/* t1 = 3 * g4^2 - 2 * g3. */
			fp2_sub(t1[i], t0[i], a[i][0][2]);
			fp2_dbl(t1[i], t1[i]);
			fp2_add(t1[i], t1[i], t0[i]);
			/* t0 = E * g5^2 + t1. */
			fp2_sqr(t2[i], a[i][1][2]);
			fp2_mul_nor(t0[i], t2[i]);
			fp2_add(t0[i], t0[i], t1[i]);
			/* t1 = (4 * g2). */
			fp2_dbl(t1[i], a[i][1][0]);
			fp2_dbl(t1[i], t1[i]);
			fp2_copy_sec(t1[i], a[i][0][2], f);
			/* If unity, decompress to unity as well. */
			f = (fp12_cmp_dig(a[i], 1) == RLC_EQ);
			fp2_set_dig(t2[i], 1);
			fp2_copy_sec(t1[i], t2[i], f);
		}

		/* t1 = 1 / t1. */
		fp2_inv_sim(t1, t1, n);

		for (int i = 0; i < n; i++) {
			/* t0 = g1. */
			fp2_mul(c[i][1][1], t0[i], t1[i]);

			/* t1 = g3 * g4. */
			fp2_mul(t1[i], a[i][0][2], a[i][0][1]);
			/* t2 = 2 * g1^2 - 3 * g3 * g4. */
			fp2_sqr(t2[i], c[i][1][1]);
			fp2_sub(t2[i], t2[i], t1[i]);
			fp2_dbl(t2[i], t2[i]);
			fp2_sub(t2[i], t2[i], t1[i]);
			/* t1 = g2 * g5. */
			fp2_mul(t1[i], a[i][1][0], a[i][1][2]);
			/* t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
			fp2_add(t2[i], t2[i], t1[i]);
			fp2_mul_nor(c[i][0][0], t2[i]);
			fp_add_dig(c[i][0][0][0], c[i][0][0][0], 1);

			fp2_copy(c[i][0][1], a[i][0][1]);
			fp2_copy(c[i][0][2], a[i][0][2]);
			fp2_copy(c[i][1][0], a[i][1][0]);
			fp2_copy(c[i][1][2], a[i][1][2]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (int i = 0; i < n; i++) {
			fp2_free(t0[i]);
			fp2_free(t1[i]);
			fp2_free(t2[i]);
		}
		RLC_FREE(t);
	}
}

void fp12_exp_cyc(fp12_t c, const fp12_t a, const bn_t b) {
	size_t j, k, l, w = bn_ham(b);

	if (bn_is_zero(b)) {
		return fp12_set_dig(c, 1);
	}

	if ((bn_bits(b) > RLC_DIG) && ((bn_ham(b) << 3) > bn_bits(b))) {
		fp12_t r, s, t[1 << (RLC_WIDTH - 2)];
		int8_t naf[RLC_FP_BITS + 1], *k, w = RLC_WIDTH;

		if (bn_bits(b) <= RLC_DIG) {
			w = 2;
		}

		fp12_null(r);
		fp12_null(s);

		RLC_TRY {
			fp12_new(r);
			fp12_new(s);
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
				fp12_null(t[i]);
				fp12_new(t[i]);
			}

#if RLC_WIDTH > 2
			fp12_sqr_cyc(t[0], a);
			fp12_mul(t[1], t[0], a);
			for (int i = 2; i < (1 << (w - 2)); i++) {
				fp12_mul(t[i], t[i - 1], t[0]);
			}
#endif
			fp12_copy(t[0], a);

			l = RLC_FP_BITS + 1;
			fp12_set_dig(r, 1);
			bn_rec_naf(naf, &l, b, w);

			k = naf + l - 1;
			for (int i = l - 1; i >= 0; i--, k--) {
				fp12_sqr_cyc(r, r);

				if (*k > 0) {
					fp12_mul(r, r, t[*k / 2]);
				}
				if (*k < 0) {
					fp12_inv_cyc(s, t[-*k / 2]);
					fp12_mul(r, r, s);
				}
			}

			if (bn_sign(b) == RLC_NEG) {
				fp12_inv_cyc(c, r);
			} else {
				fp12_copy(c, r);
			}
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp12_free(r);
			fp12_free(s);
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
				fp12_free(t[i]);
			}
		}
	} else {
		fp12_t t, *u = RLC_ALLOCA(fp12_t, w);

		fp12_null(t);

		RLC_TRY {
			if (u == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			for (int i = 0; i < w; i++) {
				fp12_null(u[i]);
				fp12_new(u[i]);
			}
			fp12_new(t);

			j = 0;
			fp12_copy(t, a);
			for (size_t i = 1; i < bn_bits(b); i++) {
				fp12_sqr_pck(t, t);
				if (bn_get_bit(b, i)) {
					fp12_copy(u[j++], t);
				}
			}

			if (!bn_is_even(b)) {
				j = 0;
				k = w - 1;
			} else {
				j = 1;
				k = w;
			}

			fp12_back_cyc_sim(u, u, k);

			if (!bn_is_even(b)) {
				fp12_copy(c, a);
			} else {
				fp12_copy(c, u[0]);
			}

			for (size_t i = j; i < k; i++) {
				fp12_mul(c, c, u[i]);
			}

			if (bn_sign(b) == RLC_NEG) {
				fp12_inv_cyc(c, c);
			}
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			for (size_t i = 0; i < w; i++) {
				fp12_free(u[i]);
			}
			fp12_free(t);
			RLC_FREE(u);
		}
	}
}

void fp12_exp_cyc_sim(fp12_t e, const fp12_t a, const bn_t b, const fp12_t c,
		const bn_t d) {
	int i, j, l;
	bn_t _b[4], _d[4], n, x;
	fp12_t t[4], u[4];

	if (bn_is_zero(b)) {
		return fp12_exp_cyc(e, c, d);
	}

	if (bn_is_zero(d)) {
		return fp12_exp_cyc(e, a, b);
	}

	bn_null(n);
	bn_null(x);

	RLC_TRY {
		bn_new(n);
		bn_new(x);
		for (i = 0; i < 4; i++) {
			bn_null(_b[i]);
			bn_null(_d[i]);
			fp12_null(t[i]);
			fp12_null(u[i]);
			bn_new(_b[i]);
			bn_new(_d[i]);
			fp12_new(t[i]);
			fp12_new(u[i]);
		}

		ep_curve_get_ord(n);
		fp_prime_get_par(x);
		bn_abs(_b[0], b);
		bn_mod(_b[0], _b[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_b[0], _b[0]);
		}
		bn_rec_frb(_b, 4, _b[0], x, n, ep_curve_is_pairf() == EP_BN);
		bn_abs(_d[0], d);
		bn_mod(_d[0], _d[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_d[0], _d[0]);
		}
		bn_rec_frb(_d, 4, _d[0], x, n, ep_curve_is_pairf() == EP_BN);

		if (ep_curve_is_pairf() && ep_curve_embed() == 12) {
			for (i = 0; i < 4; i++) {
				fp12_frb(t[i], a, i);
				fp12_frb(u[i], c, i);
				if (bn_sign(_b[i]) == RLC_NEG) {
					fp12_inv_cyc(t[i], t[i]);
				}
				if (bn_sign(_d[i]) == RLC_NEG) {
					fp12_inv_cyc(u[i], u[i]);
				}
			}

			l = RLC_MAX(bn_bits(_b[0]), bn_bits(_b[1]));
			l = RLC_MAX(l, RLC_MAX(bn_bits(_b[2]), bn_bits(_b[3])));
			l = RLC_MAX(l, RLC_MAX(bn_bits(_d[0]), bn_bits(_d[1])));
			l = RLC_MAX(l, RLC_MAX(bn_bits(_d[2]), bn_bits(_d[3])));

			fp12_set_dig(e, 1);
			for (i = l - 1; i >= 0; i--) {
				fp12_sqr_cyc(e, e);
				for (j = 0; j < 4; j++) {
					if (bn_get_bit(_b[j], i)) {
						fp12_mul(e, e, t[j]);
					}
					if (bn_get_bit(_d[j], i)) {
						fp12_mul(e, e, u[j]);
					}
				}
			}
		} else {
			if (bn_sign(b) == RLC_NEG) {
				fp12_inv_cyc(t[0], a);
			} else {
				fp12_copy(t[0], a);
			}
			if (bn_sign(d) == RLC_NEG) {
				fp12_inv_cyc(u[0], c);
			} else {
				fp12_copy(u[0], c);
			}

			fp12_set_dig(e, 1);
			l = RLC_MAX(bn_bits(b), bn_bits(d));
			for (i = l - 1; i >= 0; i--) {
				fp12_sqr_cyc(e, e);
				if (bn_get_bit(b, i)) {
					fp12_mul(e, e, t[0]);
				}
				if (bn_get_bit(d, i)) {
					fp12_mul(e, e, u[0]);
				}
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(x);
		for (i = 0; i < 4; i++) {
			bn_free(_b[i]);
			bn_free(_d[i]);
			fp12_free(t[i]);
			fp12_free(u[i]);
		}
	}
}

void fp12_exp_cyc_sps(fp12_t c, const fp12_t a, const int *b, size_t len,
		int sign) {
	size_t i, j, k, w = len;
    fp12_t t, *u = RLC_ALLOCA(fp12_t, w);

	if (len == 0) {
		RLC_FREE(u);
		fp12_set_dig(c, 1);
		return;
	}

	fp12_null(t);

	RLC_TRY {
		if (u == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < w; i++) {
			fp12_null(u[i]);
			fp12_new(u[i]);
		}
		fp12_new(t);

		fp12_copy(t, a);
		if (b[0] == 0) {
			for (j = 0, i = 1; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp12_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp12_inv_cyc(u[i - 1], t);
				} else {
					fp12_copy(u[i - 1], t);
				}
			}

			fp12_back_cyc_sim(u, u, w - 1);

			fp12_copy(c, a);
			for (i = 0; i < w - 1; i++) {
				fp12_mul(c, c, u[i]);
			}
		} else {
			for (j = 0, i = 0; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp12_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp12_inv_cyc(u[i], t);
				} else {
					fp12_copy(u[i], t);
				}
			}

			fp12_back_cyc_sim(u, u, w);

			fp12_copy(c, u[0]);
			for (i = 1; i < w; i++) {
				fp12_mul(c, c, u[i]);
			}
		}

		if (sign == RLC_NEG) {
			fp12_inv_cyc(c, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < w; i++) {
			fp12_free(u[i]);
		}
		fp12_free(t);
		RLC_FREE(u);
	}
}































