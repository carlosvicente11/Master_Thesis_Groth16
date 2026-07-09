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
 * Implementation of comparison in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp2_cmp(const fp2_t a, const fp2_t b) {
	return (fp_cmp(a[0], b[0]) == RLC_EQ) && (fp_cmp(a[1], b[1]) == RLC_EQ) ?
			RLC_EQ : RLC_NE;
}

int fp2_cmp_dig(const fp2_t a, const dig_t b) {
	return (fp_cmp_dig(a[0], b) == RLC_EQ) && fp_is_zero(a[1]) ?
			RLC_EQ : RLC_NE;
}



int fp4_cmp(const fp4_t a, const fp4_t b) {
	return (fp2_cmp(a[0], b[0]) == RLC_EQ) && (fp2_cmp(a[1], b[1]) == RLC_EQ) ?
			RLC_EQ : RLC_NE;
}

int fp4_cmp_dig(const fp4_t a, const dig_t b) {
	return (fp2_cmp_dig(a[0], b) == RLC_EQ) && fp2_is_zero(a[1]) ?
			RLC_EQ : RLC_NE;
}

int fp6_cmp(const fp6_t a, const fp6_t b) {
	return (fp2_cmp(a[0], b[0]) == RLC_EQ) && (fp2_cmp(a[1], b[1]) == RLC_EQ) &&
			(fp2_cmp(a[2], b[2]) == RLC_EQ) ? RLC_EQ : RLC_NE;
}

int fp6_cmp_dig(const fp6_t a, const dig_t b) {
	return (fp2_cmp_dig(a[0], b) == RLC_EQ) && fp2_is_zero(a[1]) &&
			fp2_is_zero(a[2]) ?	RLC_EQ : RLC_NE;
}





int fp12_cmp(const fp12_t a, const fp12_t b) {
	return (fp6_cmp(a[0], b[0]) == RLC_EQ) && (fp6_cmp(a[1], b[1]) == RLC_EQ) ?
			RLC_EQ : RLC_NE;
}

int fp12_cmp_dig(const fp12_t a, const dig_t b) {
	return (fp6_cmp_dig(a[0], b) == RLC_EQ) && fp6_is_zero(a[1]) ?
			RLC_EQ : RLC_NE;
}










