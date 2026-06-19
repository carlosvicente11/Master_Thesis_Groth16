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

.text

.global fp_rdcn_low
.thumb_func
.type fp_rdcn_low, %function

/*============================================================================*/
/* Montgomery reduction (REDC), Separated Operand Scanning with UMAAL.         */
/*                                                                            */
/*   fp_rdcn_low(c = r0, a = r1):  c = a * 2^-256 mod p,  a is 16 words.       */
/*                                                                            */
/* The 16-word operand is copied to a stack buffer S (the input a is left     */
/* untouched, per the existing contract). For each i in 0..7:                 */
/*   m = S[i] * u  (mod 2^32), u = -p^-1 mod 2^32                             */
/*   S[i..i+7] += m * p   with a single running carry, then ripple the carry  */
/*   into S[i+8..15].                                                         */
/* UMAAL (Rn*Rm + RdLo + RdHi) keeps the carry one word wide, so the inner    */
/* loop needs no ADDS/ADCS/ADC chains. p[0..7] are held resident in r4-r11 to */
/* avoid reloading the prime constants on every product. The numerator stays  */
/* < 2^512 (no 17th word) and the result is < 2p, so a single conditional     */
/* subtract of p finishes the reduction.                                      */
/*============================================================================*/

#define P7H 0x3064
#define P7L 0x4E72
#define P6H 0xE131
#define P6L 0xA029
#define P5H 0xB850
#define P5L 0x45B6
#define P4H 0x8181
#define P4L 0x585D
#define P3H 0x9781
#define P3L 0x6A91
#define P2H 0x6871
#define P2L 0xCA8D
#define P1H 0x3C20
#define P1L 0x8C16
#define P0H 0xD87C
#define P0L 0xFD47

#define UH 0xE486
#define UL 0x6389

/* One reduction row i: m = S[i]*u; S[i..i+7] += m*p; ripple carry up. */
.macro RROW i
    LDR  r1, [r2, #(4*\i)]            @ S[i]
    MUL  r3, r1, r12                  @ m = S[i] * u   (low 32 bits)
    MOV  r14, #0                      @ C = 0
    UMAAL r1, r14, r3, r4             @ j=0: low word -> 0 (discard r1)
    LDR  r0, [r2, #(4*((\i)+1))]
    UMAAL r0, r14, r3, r5
    STR  r0, [r2, #(4*((\i)+1))]
    LDR  r0, [r2, #(4*((\i)+2))]
    UMAAL r0, r14, r3, r6
    STR  r0, [r2, #(4*((\i)+2))]
    LDR  r0, [r2, #(4*((\i)+3))]
    UMAAL r0, r14, r3, r7
    STR  r0, [r2, #(4*((\i)+3))]
    LDR  r0, [r2, #(4*((\i)+4))]
    UMAAL r0, r14, r3, r8
    STR  r0, [r2, #(4*((\i)+4))]
    LDR  r0, [r2, #(4*((\i)+5))]
    UMAAL r0, r14, r3, r9
    STR  r0, [r2, #(4*((\i)+5))]
    LDR  r0, [r2, #(4*((\i)+6))]
    UMAAL r0, r14, r3, r10
    STR  r0, [r2, #(4*((\i)+6))]
    LDR  r0, [r2, #(4*((\i)+7))]
    UMAAL r0, r14, r3, r11
    STR  r0, [r2, #(4*((\i)+7))]
    @ ripple carry C (r14) into S[i+8 .. 15]
    .set RK, (\i)+8
    LDR  r0, [r2, #(4*RK)]
    ADDS r0, r0, r14
    STR  r0, [r2, #(4*RK)]
    .rept (7-(\i))
      .set RK, RK+1
      LDR  r0, [r2, #(4*RK)]
      ADCS r0, r0, #0
      STR  r0, [r2, #(4*RK)]
    .endr
.endm

fp_rdcn_low:
    PUSH {r4-r11, lr}
    SUB  sp, sp, #72                  @ S[0..15] (64B) + saved c (4B) + pad
    STR  r0, [sp, #64]                @ save c pointer
    MOV  r2, sp                       @ S = sp

    /* Copy a[0..15] -> S, using r4-r11 as scratch before p is loaded. */
    LDMIA r1!, {r4-r11}
    STMIA r2!, {r4-r11}
    LDMIA r1!, {r4-r11}
    STMIA r2!, {r4-r11}
    SUB  r2, r2, #64                  @ reset S base

    /* Load the prime p (resident) and the Montgomery constant u. */
    MOVW r4,  #P0L
    MOVT r4,  #P0H
    MOVW r5,  #P1L
    MOVT r5,  #P1H
    MOVW r6,  #P2L
    MOVT r6,  #P2H
    MOVW r7,  #P3L
    MOVT r7,  #P3H
    MOVW r8,  #P4L
    MOVT r8,  #P4H
    MOVW r9,  #P5L
    MOVT r9,  #P5H
    MOVW r10, #P6L
    MOVT r10, #P6H
    MOVW r11, #P7L
    MOVT r11, #P7H
    MOVW r12, #UL
    MOVT r12, #UH

    RROW 0
    RROW 1
    RROW 2
    RROW 3
    RROW 4
    RROW 5
    RROW 6
    RROW 7

    /* Result is S[8..15] (< 2p). Load it, conditionally subtract p into c. */
    LDR  r5,  [r2, #(4*8)]
    LDR  r6,  [r2, #(4*9)]
    LDR  r7,  [r2, #(4*10)]
    LDR  r8,  [r2, #(4*11)]
    LDR  r9,  [r2, #(4*12)]
    LDR  r10, [r2, #(4*13)]
    LDR  r11, [r2, #(4*14)]
    LDR  r12, [r2, #(4*15)]
    LDR  r0,  [sp, #64]               @ c pointer

    /* Compare S[8..15] (r5 low .. r12 high) against p, MS word first. */
    MOVW r3, #P7L
    MOVT r3, #P7H
    CMP  r12, r3
    BHI  RDC_SUB
    BLO  RDC_NOSUB
    MOVW r3, #P6L
    MOVT r3, #P6H
    CMP  r11, r3
    BHI  RDC_SUB
    BLO  RDC_NOSUB
    MOVW r3, #P5L
    MOVT r3, #P5H
    CMP  r10, r3
    BHI  RDC_SUB
    BLO  RDC_NOSUB
    MOVW r3, #P4L
    MOVT r3, #P4H
    CMP  r9, r3
    BHI  RDC_SUB
    BLO  RDC_NOSUB
    MOVW r3, #P3L
    MOVT r3, #P3H
    CMP  r8, r3
    BHI  RDC_SUB
    BLO  RDC_NOSUB
    MOVW r3, #P2L
    MOVT r3, #P2H
    CMP  r7, r3
    BHI  RDC_SUB
    BLO  RDC_NOSUB
    MOVW r3, #P1L
    MOVT r3, #P1H
    CMP  r6, r3
    BHI  RDC_SUB
    BLO  RDC_NOSUB
    MOVW r3, #P0L
    MOVT r3, #P0H
    CMP  r5, r3
    BLO  RDC_NOSUB
    /* >= p (including all-equal): fall through to subtract. */

RDC_SUB:
    MOVW r3, #P0L
    MOVT r3, #P0H
    SUBS r5, r5, r3
    STR  r5, [r0, #0]
    MOVW r3, #P1L
    MOVT r3, #P1H
    SBCS r6, r6, r3
    STR  r6, [r0, #4]
    MOVW r3, #P2L
    MOVT r3, #P2H
    SBCS r7, r7, r3
    STR  r7, [r0, #8]
    MOVW r3, #P3L
    MOVT r3, #P3H
    SBCS r8, r8, r3
    STR  r8, [r0, #12]
    MOVW r3, #P4L
    MOVT r3, #P4H
    SBCS r9, r9, r3
    STR  r9, [r0, #16]
    MOVW r3, #P5L
    MOVT r3, #P5H
    SBCS r10, r10, r3
    STR  r10, [r0, #20]
    MOVW r3, #P6L
    MOVT r3, #P6H
    SBCS r11, r11, r3
    STR  r11, [r0, #24]
    MOVW r3, #P7L
    MOVT r3, #P7H
    SBCS r12, r12, r3
    STR  r12, [r0, #28]
    B    RDC_DONE

RDC_NOSUB:
    STR  r5,  [r0, #0]
    STR  r6,  [r0, #4]
    STR  r7,  [r0, #8]
    STR  r8,  [r0, #12]
    STR  r9,  [r0, #16]
    STR  r10, [r0, #20]
    STR  r11, [r0, #24]
    STR  r12, [r0, #28]

RDC_DONE:
    ADD  sp, sp, #72
    POP  {r4-r11, pc}

.end
