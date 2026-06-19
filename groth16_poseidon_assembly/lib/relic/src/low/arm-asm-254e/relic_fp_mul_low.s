/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2015 RELIC Authors
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

#include "relic_fp_low.h"

.syntax unified
.arch armv7e-m
.thumb

.global fp_muln_low
.thumb_func
.type fp_muln_low, %function

/*============================================================================*/
/* 256x256 -> 512 schoolbook multiply, operand-scanning with UMAAL.            */
/*                                                                            */
/* UMAAL RdLo, RdHi, Rn, Rm  computes  Rn*Rm + RdLo + RdHi  into RdHi:RdLo.    */
/* Because a*b + c + d <= (2^32-1)^2 + 2(2^32-1) = 2^64-1, the running carry   */
/* is always a single word: no ADDS/ADCS/ADC carry chains are needed.         */
/*                                                                            */
/* Register use:                                                              */
/*   r0  = C  (16-word product, written in place; not pre-zeroed)             */
/*   r1  = A  (8 words, streamed one limb per row)                            */
/*   r4..r11 = B[0..7]  (resident for the whole multiply)                     */
/*   r3  = a[i]  (current A limb)                                             */
/*   r2  = running carry for the current row                                  */
/*   r12 = current result word (UMAAL low half)                              */
/*============================================================================*/

/* One operand-scanning row: C[i..i+7] += a[i] * B[], carry out to C[i+8]. */
.macro MROW i
    LDR  r3,  [r1, #(4*\i)]
    MOV  r2,  #0
    LDR  r12, [r0, #(4*((\i)+0))]
    UMAAL r12, r2, r3, r4
    STR  r12, [r0, #(4*((\i)+0))]
    LDR  r12, [r0, #(4*((\i)+1))]
    UMAAL r12, r2, r3, r5
    STR  r12, [r0, #(4*((\i)+1))]
    LDR  r12, [r0, #(4*((\i)+2))]
    UMAAL r12, r2, r3, r6
    STR  r12, [r0, #(4*((\i)+2))]
    LDR  r12, [r0, #(4*((\i)+3))]
    UMAAL r12, r2, r3, r7
    STR  r12, [r0, #(4*((\i)+3))]
    LDR  r12, [r0, #(4*((\i)+4))]
    UMAAL r12, r2, r3, r8
    STR  r12, [r0, #(4*((\i)+4))]
    LDR  r12, [r0, #(4*((\i)+5))]
    UMAAL r12, r2, r3, r9
    STR  r12, [r0, #(4*((\i)+5))]
    LDR  r12, [r0, #(4*((\i)+6))]
    UMAAL r12, r2, r3, r10
    STR  r12, [r0, #(4*((\i)+6))]
    LDR  r12, [r0, #(4*((\i)+7))]
    UMAAL r12, r2, r3, r11
    STR  r12, [r0, #(4*((\i)+7))]
    STR  r2,  [r0, #(4*((\i)+8))]
.endm

fp_muln_low:
    PUSH {r4-r11, lr}

    LDM  r2, {r4-r11}              @ B[0..7] resident

    /* Row 0: result is logically zero, so seed each word from 0 (in r12). */
    LDR  r3, [r1, #(4*0)]         @ a[0]
    MOV  r2, #0                   @ carry
    MOV  r12, #0
    UMAAL r12, r2, r3, r4
    STR  r12, [r0, #(4*0)]
    MOV  r12, #0
    UMAAL r12, r2, r3, r5
    STR  r12, [r0, #(4*1)]
    MOV  r12, #0
    UMAAL r12, r2, r3, r6
    STR  r12, [r0, #(4*2)]
    MOV  r12, #0
    UMAAL r12, r2, r3, r7
    STR  r12, [r0, #(4*3)]
    MOV  r12, #0
    UMAAL r12, r2, r3, r8
    STR  r12, [r0, #(4*4)]
    MOV  r12, #0
    UMAAL r12, r2, r3, r9
    STR  r12, [r0, #(4*5)]
    MOV  r12, #0
    UMAAL r12, r2, r3, r10
    STR  r12, [r0, #(4*6)]
    MOV  r12, #0
    UMAAL r12, r2, r3, r11
    STR  r12, [r0, #(4*7)]
    STR  r2, [r0, #(4*8)]

    MROW 1
    MROW 2
    MROW 3
    MROW 4
    MROW 5
    MROW 6
    MROW 7

    POP {r4-r11, pc}
