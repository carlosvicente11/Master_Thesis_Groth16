/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of exponentiation in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_exp(fp2_t c, const fp2_t a, const bn_t b) {
	fp2_t t;

	if (bn_is_zero(b)) {
		fp2_set_dig(c, 1);
		return;
	}

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		fp2_copy(t, a);
		for (int i = bn_bits(b) - 2; i >= 0; i--) {
			fp2_sqr(t, t);
			if (bn_get_bit(b, i)) {
				fp2_mul(t, t, a);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp2_inv(c, t);
		} else {
			fp2_copy(c, t);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}

void fp2_exp_dig(fp2_t c, const fp2_t a, dig_t b) {
	fp2_t t;

	if (b == 0) {
		fp2_set_dig(c, 1);
		return;
	}

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		fp2_copy(t, a);
		for (int i = util_bits_dig(b) - 2; i >= 0; i--) {
			fp2_sqr(t, t);
			if (b & ((dig_t)1 << i)) {
				fp2_mul(t, t, a);
			}
		}

		fp2_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}


void fp4_exp(fp4_t c, const fp4_t a, const bn_t b) {
	fp4_t t;

	if (bn_is_zero(b)) {
		fp4_set_dig(c, 1);
		return;
	}

	fp4_null(t);

	RLC_TRY {
		fp4_new(t);

		fp4_copy(t, a);

		for (int i = bn_bits(b) - 2; i >= 0; i--) {
			fp4_sqr(t, t);
			if (bn_get_bit(b, i)) {
				fp4_mul(t, t, a);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp4_inv(c, t);
		} else {
			fp4_copy(c, t);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(t);
	}
}

void fp6_exp(fp6_t c, const fp6_t a, const bn_t b) {
	fp6_t t;

	if (bn_is_zero(b)) {
		fp6_set_dig(c, 1);
		return;
	}

	fp6_null(t);

	RLC_TRY {
		fp6_new(t);

		fp6_copy(t, a);

		for (int i = bn_bits(b) - 2; i >= 0; i--) {
			fp6_sqr(t, t);
			if (bn_get_bit(b, i)) {
				fp6_mul(t, t, a);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp6_inv(c, t);
		} else {
			fp6_copy(c, t);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp6_free(t);
	}
}




void fp12_exp(fp12_t c, const fp12_t a, const bn_t b) {
	fp12_t t;

	if (bn_is_zero(b)) {
		fp12_set_dig(c, 1);
		return;
	}

	fp12_null(t);

	RLC_TRY {
		fp12_new(t);

		if (fp12_test_cyc(a)) {
			fp12_exp_cyc(c, a, b);
		} else {
			fp12_copy(t, a);

			for (int i = bn_bits(b) - 2; i >= 0; i--) {
				fp12_sqr(t, t);
				if (bn_get_bit(b, i)) {
					fp12_mul(t, t, a);
				}
			}

			if (bn_sign(b) == RLC_NEG) {
				fp12_inv(c, t);
			} else {
				fp12_copy(c, t);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free(t);
	}
}

void fp12_exp_dig(fp12_t c, const fp12_t a, dig_t b) {
	bn_t _b;
	fp12_t t, v;
	int8_t u, naf[RLC_DIG + 1];
	size_t l;

	if (b == 0) {
		fp12_set_dig(c, 1);
		return;
	}

	bn_null(_b);
	fp12_null(t);
	fp12_null(v);

	RLC_TRY {
		bn_new(_b);
		fp12_new(t);
		fp12_new(v);

		fp12_copy(t, a);

		if (fp12_test_cyc(a)) {
			fp12_inv_cyc(v, a);
			bn_set_dig(_b, b);

			l = RLC_DIG + 1;
			bn_rec_naf(naf, &l, _b, 2);

			for (int i = bn_bits(_b) - 2; i >= 0; i--) {
				fp12_sqr_cyc(t, t);

				u = naf[i];
				if (u > 0) {
					fp12_mul(t, t, a);
				} else if (u < 0) {
					fp12_mul(t, t, v);
				}
			}
		} else {
			for (int i = util_bits_dig(b) - 2; i >= 0; i--) {
				fp12_sqr(t, t);
				if (b & ((dig_t)1 << i)) {
					fp12_mul(t, t, a);
				}
			}
		}

		fp12_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(_b);
		fp12_free(t);
		fp12_free(v);
	}
}










