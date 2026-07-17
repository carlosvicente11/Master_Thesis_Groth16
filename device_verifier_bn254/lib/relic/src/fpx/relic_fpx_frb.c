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
 * Implementation of frobenius action in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_frb(fp2_t c, const fp2_t a, int i) {
	switch (i % 2) {
		case 0:
			fp2_copy(c, a);
			break;
		case 1:
			/* (a_0 + a_1 * u)^p = a_0 - a_1 * u. */
			fp_copy(c[0], a[0]);
			fp_neg(c[1], a[1]);
			break;
	}
}


void fp4_frb(fp4_t c, const fp4_t a, int i) {
	/* Cost of a single multiplication in Fp^2 per Frobenius. */
	fp4_copy(c, a);
	for (; i % 4 > 0; i--) {
		fp2_frb(c[0], c[0], 1);
		fp2_frb(c[1], c[1], 1);
		if (fp_prime_get_mod18() % 3 == 1) {
			fp2_mul_frb(c[1], c[1], 1, 3);
		} else {
			fp2_mul_frb(c[1], c[1], 2, 1);
			fp2_mul_frb(c[1], c[1], 2, 1);
		}
	}
}

void fp6_frb(fp6_t c, const fp6_t a, int i) {
	/* Cost of two multiplication in Fp^2 per Frobenius. */
	fp6_copy(c, a);
	for (; i % 6 > 0; i--) {
		fp2_frb(c[0], c[0], 1);
		fp2_frb(c[1], c[1], 1);
		fp2_frb(c[2], c[2], 1);
		fp2_mul_frb(c[1], c[1], 1, 2);
		fp2_mul_frb(c[2], c[2], 1, 4);
	}
}



void fp12_frb(fp12_t c, const fp12_t a, int i) {
	/* Cost of five multiplication in Fp^2 per Frobenius. */
	fp12_copy(c, a);
	for (; i % 12 > 0; i--) {
		fp6_frb(c[0], c[0], 1);
		fp2_frb(c[1][0], c[1][0], 1);
		fp2_frb(c[1][1], c[1][1], 1);
		fp2_frb(c[1][2], c[1][2], 1);
		fp2_mul_frb(c[1][0], c[1][0], 1, 1);
		fp2_mul_frb(c[1][1], c[1][1], 1, 3);
		fp2_mul_frb(c[1][2], c[1][2], 1, 5);
	}
}





