/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2014 RELIC Authors
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
 * Implementation of the low-level extension field addition functions.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_addn_low(fp2_t c, fp2_t a, fp2_t b) {
	fp_addn_low(c[0], a[0], b[0]);
	fp_addn_low(c[1], a[1], b[1]);
}

void fp2_addm_low(fp2_t c, fp2_t a, fp2_t b) {
	fp_addm_low(c[0], a[0], b[0]);
	fp_addm_low(c[1], a[1], b[1]);
}

void fp2_addd_low(dv2_t c, dv2_t a, dv2_t b) {
	fp_addd_low(c[0], a[0], b[0]);
	fp_addd_low(c[1], a[1], b[1]);
}

void fp2_addc_low(dv2_t c, dv2_t a, dv2_t b) {
	fp_addc_low(c[0], a[0], b[0]);
	fp_addc_low(c[1], a[1], b[1]);
}

void fp2_subn_low(fp2_t c, fp2_t a, fp2_t b) {
	fp_subn_low(c[0], a[0], b[0]);
	fp_subn_low(c[1], a[1], b[1]);
}

void fp2_subm_low(fp2_t c, fp2_t a, fp2_t b) {
	fp_subm_low(c[0], a[0], b[0]);
	fp_subm_low(c[1], a[1], b[1]);
}

void fp2_subd_low(dv2_t c, dv2_t a, dv2_t b) {
	fp_subd_low(c[0], a[0], b[0]);
	fp_subd_low(c[1], a[1], b[1]);
}

void fp2_subc_low(dv2_t c, dv2_t a, dv2_t b) {
	fp_subc_low(c[0], a[0], b[0]);
	fp_subc_low(c[1], a[1], b[1]);
}

void fp2_dbln_low(fp2_t c, fp2_t a) {
	/* 2 * (a0 + a1 * u) = 2 * a0 + 2 * a1 * u. */
	fp_dbln_low(c[0], a[0]);
	fp_dbln_low(c[1], a[1]);
}

void fp2_dblm_low(fp2_t c, fp2_t a) {
	fp_dblm_low(c[0], a[0]);
	fp_dblm_low(c[1], a[1]);
}

void fp2_norm_low(fp2_t c, fp2_t a) {
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

#ifdef FP_QNRES
		/* If p = 3 mod 8, (1 + i) is a QNR/CNR. */
		fp_copy(t[0], a[1]);
		fp_add(c[1], a[0], a[1]);
		fp_sub(c[0], a[0], t[0]);
#else
		int qnr = fp2_field_get_qnr();
		switch (fp_prime_get_mod8()) {
			case 1:
			case 5:
				/* If p = 1,5 mod 8, (i) is a QNR/CNR. */
				fp2_mul_art(c, a);
				break;
			case 3:
				if (qnr == 1) {
					fp_copy(t[0], a[1]);
					fp_add(c[1], a[0], a[1]);
					fp_sub(c[0], a[0], t[0]);
					break;
				}
				/* Otherwise, fall back to next one. */
			case 7:
				/* If p = 7 mod 8, (qnr + i) is a QNR/CNR. */
				fp2_mul_art(t, a);
				fp_mul_dig(c[0], a[0], qnr);
				fp_mul_dig(c[1], a[1], qnr);
				fp2_add(c, c, t);
				break;
		}
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}

void fp2_nord_low(dv2_t c, dv2_t a) {
#ifdef FP_QNRES
	rlc_align dig_t t[2 * RLC_FP_DIGS];
	/* If p = 3 mod 8, (1 + i) is a QNR/CNR. */
	/* (a_0 + a_1 * i) * (1 + i) = (a_0 - a_1) + (a_0 + a_1) * u. */
	dv_copy(t, a[1], 2 * RLC_FP_DIGS);
	fp_addc_low(c[1], a[0], a[1]);
	fp_subc_low(c[0], a[0], t);
#else
	int qnr = fp2_field_get_qnr();
	dv2_t t;

	dv2_null(t);

	RLC_TRY {
		dv2_new(t);

		switch (fp_prime_get_mod8()) {
			case 1:
			case 5:
				/* If p = 1,5 mod 8, (i) is a QNR. */
				dv_copy(t[0], a[0], 2 * RLC_FP_DIGS);
				dv_zero(t[1], RLC_FP_DIGS);
				dv_copy(t[1] + RLC_FP_DIGS, fp_prime_get(), RLC_FP_DIGS);
				fp_subc_low(c[0], t[1], a[1]);
				for (int i = -1; i > fp_prime_get_qnr(); i--) {
					fp_subc_low(c[0], c[0], a[1]);
				}
				dv_copy(c[1], t[0], 2 * RLC_FP_DIGS);
				break;
			case 3:
				if (qnr == 1) {
					/* If p = 3 mod 8, (1 + i) is a QNR, i^2 = -1. */
					/* (a_0 + a_1 * i) * (1 + i) = (a_0 - a_1) + (a_0 + a_1) * i. */
					dv_copy(t[0], a[1], 2 * RLC_FP_DIGS);
					fp_addc_low(c[1], a[0], a[1]);
					fp_subc_low(c[0], a[0], t[0]);
					break;
				}
				/* Otherwise, fall back to next one. */
			case 7:
				/* If p = 7 mod 8, (qnr + i) is a QNR/CNR. */
				dv_zero(t[0], 2 * RLC_FP_DIGS);
				dv_zero(t[1], 2 * RLC_FP_DIGS);
				for (int j = 0; j < qnr; j++) {
					fp_addc_low(t[0], t[0], a[0]);
					fp_addc_low(t[1], t[1], a[1]);
				}
				fp_subc_low(c[0], t[0], a[1]);
				fp_addc_low(c[1], t[1], a[0]);
				break;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv2_free(t);
	}
#endif
}











