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
 * Implementation of utilities in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_copy(fp2_t c, const fp2_t a) {
	fp_copy(c[0], a[0]);
	fp_copy(c[1], a[1]);
}

void fp2_copy_sec(fp2_t c, const fp2_t a, dig_t bit) {
	fp_copy_sec(c[0], a[0], bit);
	fp_copy_sec(c[1], a[1], bit);
}

void fp2_zero(fp2_t a) {
	fp_zero(a[0]);
	fp_zero(a[1]);
}

int fp2_is_zero(const fp2_t a) {
	return fp_is_zero(a[0]) && fp_is_zero(a[1]);
}

void fp2_rand(fp2_t a) {
	fp_rand(a[0]);
	fp_rand(a[1]);
}

void fp2_print(const fp2_t a) {
	fp_print(a[0]);
	fp_print(a[1]);
}

int fp2_size_bin(const fp2_t a, int pack) {
	if (pack) {
		if (fp2_test_cyc(a)) {
			return RLC_FP_BYTES + 1;
		} else {
			return 2 * RLC_FP_BYTES;
		}
	} else {
		return 2 * RLC_FP_BYTES;
	}
}

void fp2_read_bin(fp2_t a, const uint8_t *bin, size_t len) {
	if (len != RLC_FP_BYTES + 1 && len != 2 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == RLC_FP_BYTES + 1) {
		fp_read_bin(a[0], bin, RLC_FP_BYTES);
		fp_zero(a[1]);
		fp_set_bit(a[1], 0, bin[RLC_FP_BYTES]);
		fp2_upk(a, a);
	}
	if (len == 2 * RLC_FP_BYTES) {
		fp_read_bin(a[0], bin, RLC_FP_BYTES);
		fp_read_bin(a[1], bin + RLC_FP_BYTES, RLC_FP_BYTES);
	}
}

void fp2_write_bin(uint8_t *bin, size_t len, const fp2_t a, int pack) {
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		if (pack && fp2_test_cyc(a)) {
			if (len < RLC_FP_BYTES + 1) {
				RLC_THROW(ERR_NO_BUFFER);
				return;
			} else {
				fp2_pck(t, a);
				fp_write_bin(bin, RLC_FP_BYTES, t[0]);
				bin[RLC_FP_BYTES] = fp_get_bit(t[1], 0);
			}
		} else {
			if (len < 2 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
				return;
			} else {
				fp_write_bin(bin, RLC_FP_BYTES, a[0]);
				fp_write_bin(bin + RLC_FP_BYTES, RLC_FP_BYTES, a[1]);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}

void fp2_set_dig(fp2_t a, const dig_t b) {
	fp_set_dig(a[0], b);
	fp_zero(a[1]);
}











void fp4_copy(fp4_t c, const fp4_t a) {
	fp2_copy(c[0], a[0]);
	fp2_copy(c[1], a[1]);
}

void fp4_copy_sec(fp4_t c, const fp4_t a, dig_t bit) {
	fp2_copy_sec(c[0], a[0], bit);
	fp2_copy_sec(c[1], a[1], bit);
}

void fp4_zero(fp4_t a) {
	fp2_zero(a[0]);
	fp2_zero(a[1]);
}

int fp4_is_zero(const fp4_t a) {
	return fp2_is_zero(a[0]) && fp2_is_zero(a[1]);
}

void fp4_rand(fp4_t a) {
	fp2_rand(a[0]);
	fp2_rand(a[1]);
}

void fp4_print(const fp4_t a) {
	fp2_print(a[0]);
	fp2_print(a[1]);
}

int fp4_size_bin(const fp4_t a) {
	return 4 * RLC_FP_BYTES;
}

void fp4_read_bin(fp4_t a, const uint8_t *bin, size_t len) {
	if (len != 4 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_read_bin(a[0], bin, 2 * RLC_FP_BYTES);
	fp2_read_bin(a[1], bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
}

void fp4_write_bin(uint8_t *bin, size_t len, const fp4_t a) {
	if (len != 4 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_write_bin(bin, 2 * RLC_FP_BYTES, a[0], 0);
	fp2_write_bin(bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1], 0);
}

void fp4_set_dig(fp4_t a, const dig_t b) {
	fp2_set_dig(a[0], b);
	fp2_zero(a[1]);
}

void fp6_copy(fp6_t c, const fp6_t a) {
	fp2_copy(c[0], a[0]);
	fp2_copy(c[1], a[1]);
	fp2_copy(c[2], a[2]);
}

void fp6_copy_sec(fp6_t c, const fp6_t a, dig_t bit) {
	fp2_copy_sec(c[0], a[0], bit);
	fp2_copy_sec(c[1], a[1], bit);
	fp2_copy_sec(c[2], a[2], bit);
}

void fp6_zero(fp6_t a) {
	fp2_zero(a[0]);
	fp2_zero(a[1]);
	fp2_zero(a[2]);
}

int fp6_is_zero(const fp6_t a) {
	return fp2_is_zero(a[0]) && fp2_is_zero(a[1]) && fp2_is_zero(a[2]);
}

void fp6_rand(fp6_t a) {
	fp2_rand(a[0]);
	fp2_rand(a[1]);
	fp2_rand(a[2]);
}

void fp6_print(const fp6_t a) {
	fp2_print(a[0]);
	fp2_print(a[1]);
	fp2_print(a[2]);
}

int fp6_size_bin(const fp6_t a) {
	return 6 * RLC_FP_BYTES;
}

void fp6_read_bin(fp6_t a, const uint8_t *bin, size_t len) {
	if (len != 6 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_read_bin(a[0], bin, 2 * RLC_FP_BYTES);
	fp2_read_bin(a[1], bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
	fp2_read_bin(a[2], bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
}

void fp6_write_bin(uint8_t *bin, size_t len, const fp6_t a) {
	if (len != 6 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_write_bin(bin, 2 * RLC_FP_BYTES, a[0], 0);
	fp2_write_bin(bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1], 0);
	fp2_write_bin(bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[2], 0);
}

void fp6_set_dig(fp6_t a, const dig_t b) {
	fp2_set_dig(a[0], b);
	fp2_zero(a[1]);
	fp2_zero(a[2]);
}





















void fp12_copy(fp12_t c, const fp12_t a) {
	fp6_copy(c[0], a[0]);
	fp6_copy(c[1], a[1]);
}

void fp12_copy_sec(fp12_t c, const fp12_t a, dig_t bit) {
	fp6_copy_sec(c[0], a[0], bit);
	fp6_copy_sec(c[1], a[1], bit);
}

void fp12_zero(fp12_t a) {
	fp6_zero(a[0]);
	fp6_zero(a[1]);
}

int fp12_is_zero(const fp12_t a) {
	return (fp6_is_zero(a[0]) && fp6_is_zero(a[1]));
}

void fp12_rand(fp12_t a) {
	fp6_rand(a[0]);
	fp6_rand(a[1]);
}

void fp12_print(const fp12_t a) {
	fp6_print(a[0]);
	fp6_print(a[1]);
}

int fp12_size_bin(const fp12_t a, int pack) {
	if (pack) {
		if (fp12_test_cyc(a)) {
			return 8 * RLC_FP_BYTES;
		} else {
			return 12 * RLC_FP_BYTES;
		}
	} else {
		return 12 * RLC_FP_BYTES;
	}
}

void fp12_read_bin(fp12_t a, const uint8_t *bin, size_t len) {
	if (len != 8 * RLC_FP_BYTES && len != 12 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 8 * RLC_FP_BYTES) {
		fp2_zero(a[0][0]);
		fp2_read_bin(a[0][1], bin, 2 * RLC_FP_BYTES);
		fp2_read_bin(a[0][2], bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
		fp2_read_bin(a[1][0], bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
		fp2_zero(a[1][1]);
		fp2_read_bin(a[1][2], bin + 6 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
		fp12_back_cyc(a, a);
	}
	if (len == 12 * RLC_FP_BYTES) {
		fp6_read_bin(a[0], bin, 6 * RLC_FP_BYTES);
		fp6_read_bin(a[1], bin + 6 * RLC_FP_BYTES, 6 * RLC_FP_BYTES);
	}
}

void fp12_write_bin(uint8_t *bin, size_t len, const fp12_t a, int pack) {
	fp12_t t;

	fp12_null(t);

	RLC_TRY {
		fp12_new(t);

		if (pack) {
			if (len != 8 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp12_pck(t, a);
			fp2_write_bin(bin, 2 * RLC_FP_BYTES, a[0][1], 0);
			fp2_write_bin(bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[0][2], 0);
			fp2_write_bin(bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1][0], 0);
			fp2_write_bin(bin + 6 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1][2], 0);
		} else {
			if (len != 12 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp6_write_bin(bin, 6 * RLC_FP_BYTES, a[0]);
			fp6_write_bin(bin + 6 * RLC_FP_BYTES, 6 * RLC_FP_BYTES, a[1]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp12_free(t);
	}
}

void fp12_set_dig(fp12_t a, const dig_t b) {
	fp6_set_dig(a[0], b);
	fp6_zero(a[1]);
}


















































