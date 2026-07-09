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
 * Implementation of inversion in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_inv(fp2_t c, const fp2_t a) {
	fp_t t0, t1;

	fp_null(t0);
	fp_null(t1);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);

		/* t0 = a_0^2, t1 = a_1^2. */
		fp_sqr(t0, a[0]);
		fp_sqr(t1, a[1]);

		/* t1 = 1/(a_0^2 + a_1^2). */
#ifndef FP_QNRES
		if (fp_prime_get_qnr() != -1) {
			if (fp_prime_get_qnr() == -2) {
				fp_dbl(t1, t1);
				fp_add(t0, t0, t1);
			} else {
				if (fp_prime_get_qnr() < 0) {
					fp_mul_dig(t1, t1, -fp_prime_get_qnr());
					fp_add(t0, t0, t1);
				} else {
					fp_mul_dig(t1, t1, fp_prime_get_qnr());
					fp_sub(t0, t0, t1);
				}
			}
		} else {
			fp_add(t0, t0, t1);
		}
#else
		fp_add(t0, t0, t1);
#endif

		fp_inv(t1, t0);

		/* c_0 = a_0/(a_0^2 + a_1^2). */
		fp_mul(c[0], a[0], t1);
		/* c_1 = - a_1/(a_0^2 + a_1^2). */
		fp_mul(c[1], a[1], t1);
		fp_neg(c[1], c[1]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
	}
}

void fp2_inv_cyc(fp2_t c, const fp2_t a) {
	fp_copy(c[0], a[0]);
	fp_neg(c[1], a[1]);
}

void fp2_inv_sim(fp2_t *c, const fp2_t *a, int n) {
	int i;
	fp2_t u, *t = RLC_ALLOCA(fp2_t, n);

	for (i = 0; i < n; i++) {
		fp2_null(t[i]);
	}
	fp2_null(u);

	RLC_TRY {
		for (i = 0; i < n; i++) {
			fp2_new(t[i]);
		}
		fp2_new(u);

		fp2_copy(c[0], a[0]);
		fp2_copy(t[0], a[0]);

		for (i = 1; i < n; i++) {
			fp2_copy(t[i], a[i]);
			fp2_mul(c[i], c[i - 1], t[i]);
		}

		fp2_inv(u, c[n - 1]);

		for (i = n - 1; i > 0; i--) {
			fp2_mul(c[i], c[i - 1], u);
			fp2_mul(u, u, t[i]);
		}
		fp2_copy(c[0], u);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < n; i++) {
			fp2_free(t[i]);
		}
		fp2_free(u);
		RLC_FREE(t);
	}
}



void fp4_inv_cyc(fp4_t c, const fp4_t a) {
	fp2_copy(c[0], a[0]);
	fp2_neg(c[1], a[1]);
}

void fp4_inv(fp4_t c, const fp4_t a) {
	fp2_t t0;
	fp2_t t1;

	fp2_null(t0);
	fp2_null(t1);

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);

		fp2_sqr(t0, a[0]);
		fp2_sqr(t1, a[1]);
		fp2_mul_nor(t1, t1);
		fp2_sub(t0, t0, t1);
		fp2_inv(t0, t0);

		fp2_mul(c[0], a[0], t0);
		fp2_neg(c[1], a[1]);
		fp2_mul(c[1], c[1], t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t0);
		fp2_free(t1);
	}
}

void fp4_inv_sim(fp4_t * c, const fp4_t * a, int n) {
	int i;
	fp4_t u, *t = RLC_ALLOCA(fp4_t, n);

	for (i = 0; i < n; i++) {
		fp4_null(t[i]);
	}
	fp4_null(u);

	RLC_TRY {
		for (i = 0; i < n; i++) {
			fp4_new(t[i]);
		}
		fp4_new(u);

		fp4_copy(c[0], a[0]);
		fp4_copy(t[0], a[0]);

		for (i = 1; i < n; i++) {
			fp4_copy(t[i], a[i]);
			fp4_mul(c[i], c[i - 1], t[i]);
		}

		fp4_inv(u, c[n - 1]);

		for (i = n - 1; i > 0; i--) {
			fp4_mul(c[i], c[i - 1], u);
			fp4_mul(u, u, t[i]);
		}
		fp4_copy(c[0], u);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < n; i++) {
			fp4_free(t[i]);
		}
		fp4_free(u);
		RLC_FREE(t);
	}
}

void fp6_inv(fp6_t c, const fp6_t a) {
	fp2_t v0;
	fp2_t v1;
	fp2_t v2;
	fp2_t t0;

	fp2_null(v0);
	fp2_null(v1);
	fp2_null(v2);
	fp2_null(t0);

	RLC_TRY {
		fp2_new(v0);
		fp2_new(v1);
		fp2_new(v2);
		fp2_new(t0);

		/* v0 = a_0^2 - E * a_1 * a_2. */
		fp2_sqr(t0, a[0]);
		fp2_mul(v0, a[1], a[2]);
		fp2_mul_nor(v2, v0);
		fp2_sub(v0, t0, v2);

		/* v1 = E * a_2^2 - a_0 * a_1. */
		fp2_sqr(t0, a[2]);
		fp2_mul_nor(v2, t0);
		fp2_mul(v1, a[0], a[1]);
		fp2_sub(v1, v2, v1);

		/* v2 = a_1^2 - a_0 * a_2. */
		fp2_sqr(t0, a[1]);
		fp2_mul(v2, a[0], a[2]);
		fp2_sub(v2, t0, v2);

		fp2_mul(t0, a[1], v2);
		fp2_mul_nor(c[1], t0);

		fp2_mul(c[0], a[0], v0);

		fp2_mul(t0, a[2], v1);
		fp2_mul_nor(c[2], t0);

		fp2_add(t0, c[0], c[1]);
		fp2_add(t0, t0, c[2]);
		fp2_inv(t0, t0);

		fp2_mul(c[0], v0, t0);
		fp2_mul(c[1], v1, t0);
		fp2_mul(c[2], v2, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(v0);
		fp2_free(v1);
		fp2_free(v2);
		fp2_free(t0);
	}
}






void fp12_inv(fp12_t c, const fp12_t a) {
	fp6_t t0;
	fp6_t t1;

	fp6_null(t0);
	fp6_null(t1);

	RLC_TRY {
		fp6_new(t0);
		fp6_new(t1);

		fp6_sqr(t0, a[0]);
		fp6_sqr(t1, a[1]);
		fp6_mul_art(t1, t1);
		fp6_sub(t0, t0, t1);
		fp6_inv(t0, t0);

		fp6_mul(c[0], a[0], t0);
		fp6_neg(c[1], a[1]);
		fp6_mul(c[1], c[1], t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp6_free(t0);
		fp6_free(t1);
	}
}

void fp12_inv_cyc(fp12_t c, const fp12_t a) {
	fp6_copy(c[0], a[0]);
	fp6_neg(c[1], a[1]);
}











