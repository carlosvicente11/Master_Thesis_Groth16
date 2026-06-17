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

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

.text

.global fp_rdcn_low
.thumb_func
.type fp_rdcn_low, %function

/********************************************************** FP_RDCN_LOW ***********************************************************************/

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


fp_rdcn_low:
	STMDB sp!, {r4-r12, r14}

	PLD    [r1, #32]

	MOV r3, #0
	MOV r4, #0
	MOV r5, #0

	/* COMBA_MFIN_LO_1 0 */
	LDR  r6, [r1, #(4*0)]
		MOVW r8, #P0L
		MOVT r8, #P0H
		MOVW r9, #UL
		MOVT r9, #UH
	ADDS r5, r5, r6
/*
	ADCS r4, r4, #0
	ADC  r3, r3, #0
*/
	UMULL r6, r10, r5, r9
   		MOV r12, #0
   		MOV r14, #0
   	STR r6, [r0, #(4*0)]


	UMLAL r5, r12, r6, r8
		LDR r6, [r0, #(4*0)]
    	MOVW r7, #P1L
    	MOVT r7, #P1H
	ADCS r4, r4, r12
	ADC r3, r3, #0

	/* COMBA_STEP_LO_2 0 P1 */
	UMLAL r4, r14, r6, r7
		LDR  r6, [r1, #(4*1)]
		MOV r12, #0
	ADDS r3, r3, r14
	ADC r5, r5, #0
	/* COMBA_MFIN_LO_2 1 */
	ADDS r4, r4, r6
/*
	ADCS r3, r3, #0
	ADC  r5, r5, #0
*/
	UMULL r6, r10, r4, r9
		MOV r14, #0
    STR r6, [r0, #(4*1)]

	UMLAL r4, r12, r6, r8
		LDR r6, [r0, #(4*0)]
    	MOVW r7, #P2L
    	MOVT r7, #P2H
	ADCS r3, r3, r12
	ADC r5, r5, #0

	/* COMBA_STEP_LO_3 0 P2 */

	UMLAL r3, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*1)]
		MOVW r7, #P1L
		MOVT r7, #P1H
	ADDS r5, r5, r14
	ADC r4, r4, #0
	/* COMBA_STEP_LO_3 1 P1 */

	UMLAL r3, r12, r6, r7
		LDR  r6, [r1, #(4*2)]
		MOV r14, #0
	ADDS r5, r5, r12
	ADC r4, r4, #0
	/* COMBA_MFIN_LO_3 2 */
	ADDS r3, r3, r6
/*
	ADCS r5, r5, #0
	ADC  r4, r4, #0
*/
	UMULL r6, r10, r3, r9
    STR r6, [r0, #(4*2)]

	UMLAL r3, r14, r6, r8
		MOV r12, #0
		LDR r6, [r0, #(4*0)]
		MOVW r7, #P3L
    	MOVT r7, #P3H
	ADCS r5, r5, r14
	ADC r4, r4, #0

	/* _COMBA_STEP_LO_1 0 P31 P30 */
	UMLAL r5, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*1)]
   		MOVW r7, #P2L
   		MOVT r7, #P2H
	ADDS r4, r4, r12
	ADC r3, r3, #0
	/* COMBA_STEP_LO_1 1 P2 */
	UMLAL r5, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*2)]
    	MOVW r7, #P1L
    	MOVT r7, #P1H
	ADDS r4, r4, r14
	ADC r3, r3, #0
	/* COMBA_STEP_LO_1 2 P1 */
	UMLAL r5, r12, r6, r7
		MOV r14, #0
		LDR  r6, [r1, #(4*3)]
	ADDS r4, r4, r12
	ADC r3, r3, #0
	/* COMBA_MFIN_LO_1 3 */
	ADDS r5, r5, r6
/*
	ADCS r4, r4, #0
	ADC  r3, r3, #0
*/
	UMULL r6, r10, r5, r9
   	STR r6, [r0, #(4*3)]

	UMLAL r5, r14, r6, r8
		MOV r12, #0
		LDR r6, [r0, #(4*0)]
   	 	MOVW r7, #P4L
   	 	MOVT r7, #P4H
	ADCS r4, r4, r14
	ADC r3, r3, #0

	/* COMBA_STEP_LO_2 0 P4 */

	UMLAL r4, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*1)]
		MOVW r7, #P3L
    	MOVT r7, #P3H
	ADDS r3, r3, r12
	ADC r5, r5, #0
	/* _COMBA_STEP_LO_2 1 P31 P30 */

	UMLAL r4, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*2)]
    	MOVW r7, #P2L
    	MOVT r7, #P2H
	ADDS r3, r3, r14
	ADC r5, r5, #0
	/* COMBA_STEP_LO_2 2 P2 */

	UMLAL r4, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*3)]
    	MOVW r7, #P1L
    	MOVT r7, #P1H
	ADDS r3, r3, r12
	ADC r5, r5, #0
	/* COMBA_STEP_LO_2 3 P1 */

	UMLAL r4, r14, r6, r7
		MOV r12, #0
		LDR  r6, [r1, #(4*4)]
	ADDS r3, r3, r14
	ADC r5, r5, #0
	/* COMBA_MFIN_LO_2 4 */

	ADDS r4, r4, r6
/*
	ADCS r3, r3, #0
	ADC  r5, r5, #0
*/
	UMULL r6, r10, r4, r9
    STR r6, [r0, #(4*4)]

	UMLAL r4, r12, r6, r8
		MOV r14, #0
		LDR r6, [r0, #(4*0)]
		MOVW r7, #P5L
    	MOVT r7, #P5H
	ADCS r3, r3, r12
	ADC r5, r5, #0

	/* _COMBA_STEP_LO_3 0 P51 P50 */

	UMLAL r3, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*1)]
    	MOVW r7, #P4L
    	MOVT r7, #P4H
	ADDS r5, r5, r14
	ADC r4, r4, #0
	/* COMBA_STEP_LO_3 1 P4 */

	UMLAL r3, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*2)]
		MOVW r7, #P3L
    	MOVT r7, #P3H
	ADDS r5, r5, r12
	ADC r4, r4, #0
	/* _COMBA_STEP_LO_3 2 P31 P30 */

	UMLAL r3, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*3)]
    	MOVW r7, #P2L
    	MOVT r7, #P2H
	ADDS r5, r5, r14
	ADC r4, r4, #0
	/* COMBA_STEP_LO_3 3 P2 */

	UMLAL r3, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*4)]
    	MOVW r7, #P1L
    	MOVT r7, #P1H
	ADDS r5, r5, r12
	ADC r4, r4, #0
	/* COMBA_STEP_LO_3 4 P1 */

	UMLAL r3, r14, r6, r7
		MOV r12, #0
		LDR  r6, [r1, #(4*5)]
	ADDS r5, r5, r14
	ADC r4, r4, #0
	/* COMBA_MFIN_LO_3 5 */
	ADDS r3, r3, r6
/*
	ADCS r5, r5, #0
	ADC  r4, r4, #0
*/
	UMULL r6, r10, r3, r9
    STR r6, [r0, #(4*5)]

	UMLAL r3, r12, r6, r8
		MOV r14, #0
		LDR r6, [r0, #(4*0)]
    	MOVW r7, #P6L
    	MOVT r7, #P6H
	ADCS r5, r5, r12
	ADC r4, r4, #0

	/* COMBA_STEP_LO_1 0 P6 */

	UMLAL r5, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*1)]
		MOVW r7, #P5L
    	MOVT r7, #P5H
	ADDS r4, r4, r14
	ADC r3, r3, #0
	/*_COMBA_STEP_LO_1 1 P51 P50 */

	UMLAL r5, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*2)]
    	MOVW r7, #P4L
    	MOVT r7, #P4H
	ADDS r4, r4, r12
	ADC r3, r3, #0
	/* COMBA_STEP_LO_1 2 P4 */

	UMLAL r5, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*3)]
		MOVW r7, #P3L
    	MOVT r7, #P3H
	ADDS r4, r4, r14
	ADC r3, r3, #0
	/* _COMBA_STEP_LO_1 3 P31 P30 */

	UMLAL r5, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*4)]
    	MOVW r7, #P2L
    	MOVT r7, #P2H
	ADDS r4, r4, r12
	ADC r3, r3, #0
	/* COMBA_STEP_LO_1 4 P2 */

	UMLAL r5, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*5)]
    	MOVW r7, #P1L
    	MOVT r7, #P1H
	ADDS r4, r4, r14
	ADC r3, r3, #0
	/* COMBA_STEP_LO_1 5 P1 */

	UMLAL r5, r12, r6, r7
		MOV r14, #0
		LDR  r6, [r1, #(4*6)]
	ADDS r4, r4, r12
	ADC r3, r3, #0
	/* COMBA_MFIN_LO_1 6 */
	ADDS r5, r5, r6
/*
	ADCS r4, r4, #0
	ADC  r3, r3, #0
*/
	UMULL r6, r10, r5, r9
   	STR r6, [r0, #(4*6)]

	UMLAL r5, r14, r6, r8
		MOV r12, #0
		LDR r6, [r0, #(4*0)]
		MOVW r7, #P7L
    	MOVT r7, #P7H
	ADCS r4, r4, r14
	ADC r3, r3, #0

	/* _COMBA_STEP_LO_2 0 P71 P70 */

	UMLAL r4, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*1)]
    	MOVW r7, #P6L
    	MOVT r7, #P6H
	ADDS r3, r3, r12
	ADC r5, r5, #0
	/* COMBA_STEP_LO_2 1 P6 */

	UMLAL r4, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*2)]
		MOVW r7, #P5L
    	MOVT r7, #P5H
	ADDS r3, r3, r14
	ADC r5, r5, #0
	/* _COMBA_STEP_LO_2 2 P51 P50 */

	UMLAL r4, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*3)]
    	MOVW r7, #P4L
    	MOVT r7, #P4H
	ADDS r3, r3, r12
	ADC r5, r5, #0
	/* COMBA_STEP_LO_2 3 P4 */

	UMLAL r4, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*4)]
		MOVW r7, #P3L
    	MOVT r7, #P3H
	ADDS r3, r3, r14
	ADC r5, r5, #0
	/* _COMBA_STEP_LO_2 4 P31 P30 */

	UMLAL r4, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*5)]
    	MOVW r7, #P2L
    	MOVT r7, #P2H
	ADDS r3, r3, r12
	ADC r5, r5, #0
	/* COMBA_STEP_LO_2 5 P2 */

	UMLAL r4, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*6)]
    	MOVW r7, #P1L
    	MOVT r7, #P1H
	ADDS r3, r3, r14
	ADC r5, r5, #0
	/* COMBA_STEP_LO_2 6 P1 */

	UMLAL r4, r12, r6, r7
		MOV r14, #0
		LDR  r6, [r1, #(4*7)]
	ADDS r3, r3, r12
	ADC r5, r5, #0
	/* COMBA_MFIN_LO_2 7 */
	ADDS r4, r4, r6
/*
	ADCS r3, r3, #0
	ADC  r5, r5, #0
*/
	UMULL r6, r10, r4, r9
    STR r6, [r0, #(4*7)]

	UMLAL r4, r14, r6, r8
		MOV r12, #0
		LDR r6, [r0, #(4*1)]
		MOVW r7, #P7L
    	MOVT r7, #P7H
	ADCS r3, r3, r14
	ADC r5, r5, #0

	/* _COMBA_STEP_HI_3 1 P71 P70 */

	UMLAL r3, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*2)]
    	MOVW r7, #P6L
    	MOVT r7, #P6H
	ADDS r5, r5, r12
	ADC r4, r4, #0
	/* COMBA_STEP_HI_3 2 P6 */

	UMLAL r3, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*3)]
		MOVW r7, #P5L
    	MOVT r7, #P5H
	ADDS r5, r5, r14
	ADC r4, r4, #0
	/* _COMBA_STEP_HI_3 3 P51 P50 */

	UMLAL r3, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*4)]
    	MOVW r7, #P4L
    	MOVT r7, #P4H
	ADDS r5, r5, r12
	ADC r4, r4, #0
	/* COMBA_STEP_HI_3 4 P4 */

	UMLAL r3, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*5)]
		MOVW r7, #P3L
    	MOVT r7, #P3H
	ADDS r5, r5, r14
	ADC r4, r4, #0
	/* _COMBA_STEP_HI_3 5 P31 P30 */

	UMLAL r3, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*6)]
    	MOVW r7, #P2L
    	MOVT r7, #P2H
	ADDS r5, r5, r12
	ADC r4, r4, #0
	/* COMBA_STEP_HI_3 6 P2 */

	UMLAL r3, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*7)]
    	MOVW r7, #P1L
    	MOVT r7, #P1H
	ADDS r5, r5, r14
	ADC r4, r4, #0
	/* COMBA_STEP_HI_3 7 P1 */

	UMLAL r3, r12, r6, r7
		MOV r14, #0
		LDR  r6, [r1, #(4*8)]
		MOVW r7, #P7L
    	MOVT r7, #P7H
/*
	ADDS r5, r5, r12
	ADC r4, r4, #0
*/
	/* COMBA_MFIN_HI_3 8 */
	ADDS r3, r3, r6
	ADCS r5, r5, r12
	ADC  r4, r4, #0
	LDR r6, [r0, #(4*2)]
	STR r3, [r0, #(4*(8-8))]
	MOV r3, #0

	/* _COMBA_STEP_HI_1 2 P71 P70 */

	UMLAL r5, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*3)]
    	MOVW r7, #P6L
    	MOVT r7, #P6H
	ADDS r4, r4, r14
	ADC r3, r3, #0
	/* COMBA_STEP_HI_1 3 P6 */

	UMLAL r5, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*4)]
		MOVW r7, #P5L
    	MOVT r7, #P5H
	ADDS r4, r4, r12
	ADC r3, r3, #0
	/* _COMBA_STEP_HI_1 4 P51 P50 */

	UMLAL r5, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*5)]
    	MOVW r7, #P4L
    	MOVT r7, #P4H
	ADDS r4, r4, r14
	ADC r3, r3, #0
	/* COMBA_STEP_HI_1 5 P4 */

	UMLAL r5, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*6)]
		MOVW r7, #P3L
    	MOVT r7, #P3H
	ADDS r4, r4, r12
	ADC r3, r3, #0
	/* _COMBA_STEP_HI_1 6 P31 P30 */

	UMLAL r5, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*7)]
    	MOVW r7, #P2L
    	MOVT r7, #P2H
	ADDS r4, r4, r14
	ADC r3, r3, #0
	/* COMBA_STEP_HI_1 7 P2 */

	UMLAL r5, r12, r6, r7
		MOV r14, #0
		LDR  r6, [r1, #(4*9)]
		MOVW r7, #P7L
    	MOVT r7, #P7H
/*
	ADDS r4, r4, r12
	ADC r3, r3, #0
*/
	/* COMBA_MFIN_HI_1 9 */
	ADDS r5, r5, r6
	ADCS r4, r4, r12
	ADC  r3, r3, #0
	LDR r6, [r0, #(4*3)]
	STR r5, [r0, #(4*(9-8))]
	MOV r5, #0

	/* _COMBA_STEP_HI_2 3 P71 P70 */

	UMLAL r4, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*4)]
    	MOVW r7, #P6L
    	MOVT r7, #P6H
	ADDS r3, r3, r14
	ADC r5, r5, #0
	/* COMBA_STEP_HI_2 4 P6 */

	UMLAL r4, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*5)]
		MOVW r7, #P5L
    	MOVT r7, #P5H
	ADDS r3, r3, r12
	ADC r5, r5, #0
	/* _COMBA_STEP_HI_2 5 P51 P50 */

	UMLAL r4, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*6)]
    	MOVW r7, #P4L
    	MOVT r7, #P4H
	ADDS r3, r3, r14
	ADC r5, r5, #0
	/* COMBA_STEP_HI_2 6 P4 */

	UMLAL r4, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*7)]
		MOVW r7, #P3L
    	MOVT r7, #P3H
	ADDS r3, r3, r12
	ADC r5, r5, #0
	/* _COMBA_STEP_HI_2 7 P31 P30 */

	UMLAL r4, r14, r6, r7
		MOV r12, #0
		LDR  r6, [r1, #(4*10)]
		MOVW r7, #P7L
    	MOVT r7, #P7H
/*
	ADDS r3, r3, r14
	ADC r5, r5, #0
*/
	/* COMBA_MFIN_HI_2 10 */
	ADDS r4, r4, r6
	ADCS r3, r3, r14
	ADC  r5, r5, #0
	LDR r6, [r0, #(4*4)]
	STR r4, [r0, #(4*(10-8))]
	MOV r4, #0

	/* _COMBA_STEP_HI_3 4 P71 P70 */
	UMLAL r3, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*5)]
    	MOVW r7, #P6L
    	MOVT r7, #P6H
	ADDS r5, r5, r12
	ADC r4, r4, #0
	/* COMBA_STEP_HI_3 5 P6 */
	UMLAL r3, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*6)]
		MOVW r7, #P5L
  	  MOVT r7, #P5H
	ADDS r5, r5, r14
	ADC r4, r4, #0
	/* _COMBA_STEP_HI_3 6 P51 P50 */

	UMLAL r3, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*7)]
    	MOVW r7, #P4L
    	MOVT r7, #P4H
	ADDS r5, r5, r12
	ADC r4, r4, #0
	/* COMBA_STEP_HI_3 7 P4 */

	UMLAL r3, r14, r6, r7
		MOV r12, #0
		LDR  r6, [r1, #(4*11)]
		MOVW r7, #P7L
    	MOVT r7, #P7H
/*
	ADDS r5, r5, r14
	ADC r4, r4, #0
*/
	/* COMBA_MFIN_HI_3 11 */
	ADDS r3, r3, r6
	ADCS r5, r5, r14
	ADC  r4, r4, #0
	LDR r6, [r0, #(4*5)]
	STR r3, [r0, #(4*(11-8))]
	MOV r3, #0

	/* _COMBA_STEP_HI_1 5 P71 P70 */
	UMLAL r5, r12, r6, r7
		MOV r14, #0
		LDR r6, [r0, #(4*6)]
    	MOVW r7, #P6L
    	MOVT r7, #P6H
	ADDS r4, r4, r12
	ADC r3, r3, #0
	/* COMBA_STEP_HI_1 6 P6 */

	UMLAL r5, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*7)]
		MOVW r7, #P5L
    	MOVT r7, #P5H
	ADDS r4, r4, r14
	ADC r3, r3, #0
	/* _COMBA_STEP_HI_1 7 P51 P50 */

	UMLAL r5, r12, r6, r7
		MOV r14, #0
		LDR  r6, [r1, #(4*12)]
		MOVW r7, #P7L
    	MOVT r7, #P7H
/*
	ADDS r4, r4, r12
	ADC r3, r3, #0
*/
	/* COMBA_MFIN_HI_1 12 */
	ADDS r5, r5, r6
	ADCS r4, r4, r12
	ADC  r3, r3, #0
	LDR r6, [r0, #(4*6)]
	STR r5, [r0, #(4*(12-8))]
	MOV r5, #0
	/* _COMBA_STEP_HI_2 6 P71 P70 */

	UMLAL r4, r14, r6, r7
		MOV r12, #0
		LDR r6, [r0, #(4*7)]
    	MOVW r7, #P6L
    	MOVT r7, #P6H
	ADDS r3, r3, r14
	ADC r5, r5, #0
	/* COMBA_STEP_HI_2 7 P6 */

	UMLAL r4, r12, r6, r7
		MOV r14, #0
		LDR  r6, [r1, #(4*13)]
		MOVW r7, #P7L
    	MOVT r7, #P7H
 /*
	ADDS r3, r3, r12
	ADC r5, r5, #0
*/
	/* COMBA_MFIN_HI_2 13 */
	ADDS r4, r4, r6
	ADCS r3, r3, r12
	ADC  r5, r5, #0
	LDR r6, [r0, #(4*7)]
	STR r4, [r0, #(4*(13-8))]
	MOV r4, #0

	/* _COMBA_STEP_HI_3 7 P71 P70 */
	UMLAL r3, r14, r6, r7
		MOV r12, #0
		LDR  r6, [r1, #(4*14)]
/*
	ADDS r5, r5, r14
	ADC r4, r4, #0
*/
	/* COMBA_MFIN_HI_3 14 */
	ADDS r3, r3, r6
	ADCS r5, r5, r14
	ADC  r4, r4, #0
	LDR  r6, [r1, #(4*15)]
	STR r3, [r0, #(4*(14-8))]
	MOV r3, #0

	/* COMBA_ADD_1 15 */
	ADD r5, r5, r6
/*
	ADCS r4, r4, #0
	ADC  r3, r3, #0
*/
	STR r5, [r0, #(4*7)]
	/* STR r4, [r0, #(4*8)]  Necessario? */

/* CMP_STEP: */
	LDR r5, [r0, #0]
	LDR r6, [r0, #4]
	LDR r7, [r0, #8]
	LDR r8, [r0, #12]
	LDR r9, [r0, #16]
	LDR r10, [r0, #20]
	LDR r11, [r0, #24]
	LDR r12, [r0, #28]

	/**** Primeira iteracao ****/
	MOVW r3, #P7L
	MOVT r3, #P7H
	CMP r12, r3
	BHI GREATER_THAN_OR_EQUAL
	BLO LESS_THAN

	/**** Segunda iteracao ****/
    	MOVW r3, #P6L
    	MOVT r3, #P6H
	CMP r11, r3
	BHI GREATER_THAN_OR_EQUAL
	BLO LESS_THAN

	/**** Terceira iteracao ****/
	MOVW r3, #P5L
	MOVT r3, #P5H
	CMP r10, r3
	BHI GREATER_THAN_OR_EQUAL
	BLO LESS_THAN

	/**** Quarta iteracao ****/
	MOVW r3, #P4L
	MOVT r3, #P4H
	CMP r9, r3
	BHI GREATER_THAN_OR_EQUAL
	BLO LESS_THAN

	/**** Quinta iteracao ****/
	MOVW r3, #P3L
	MOVT r3, #P3H
	CMP r8, r3
	BHI GREATER_THAN_OR_EQUAL
	BLO LESS_THAN

	/**** Sexta iteracao ****/
	MOVW r3, #P2L
	MOVT r3, #P2H
	CMP r7, r3
	BHI GREATER_THAN_OR_EQUAL
	BLO LESS_THAN

	/**** Setima iteracao ****/
	MOVW r3, #P1L
	MOVT r3, #P1H
	CMP r6, r3
	BHI GREATER_THAN_OR_EQUAL
	BLO LESS_THAN

	/**** Oitava iteracao ****/
	MOVW r3, #P0L
	MOVT r3, #P0H
	CMP r5, r3
	BHI GREATER_THAN_OR_EQUAL
	BLO LESS_THAN

GREATER_THAN_OR_EQUAL:

/*Se for maior ou igual subtrair 'p' e escrever em memoria */

/* SUB_STEP: */
	/**** Primeira iteracao ****/
	MOVW r3, #P0L
	MOVT r3, #P0H
	SUBS r5, r5, r3
	STR r5, [r0, #0]

	/**** Segunda iteracao ****/
	MOVW r3, #P1L
	MOVT r3, #P1H
	SBCS r6, r6, r3
	STR r6, [r0, #4]

	/**** Terceira iteracao ****/
	MOVW r3, #P2L
	MOVT r3, #P2H
	SBCS r7, r7, r3
	STR r7, [r0, #8]

	/**** Quarta iteracao ****/
	MOVW r3, #P3L
	MOVT r3, #P3H
	SBCS r8, r8, r3
	STR r8, [r0, #12]

	/**** Quinta iteracao ****/
	MOVW r3, #P4L
	MOVT r3, #P4H
	SBCS r9, r9, r3
	STR r9, [r0, #16]

	/**** Sexta iteracao ****/
	MOVW r3, #P5L
	MOVT r3, #P5H
	SBCS r10, r10, r3
	STR r10, [r0, #20]

	/**** Setima iteracao ****/
    	MOVW r3, #P6L
    	MOVT r3, #P6H
	SBCS r11, r11, r3
	STR r11, [r0, #24]

	/**** Oitava iteracao ****/
	MOVW r3, #P7L
	MOVT r3, #P7H
	SBCS r12, r12, r3
	STR r12, [r0, #28]

LESS_THAN:

	LDMIA sp!, {r4-r12, r14}
	MOV pc, lr

.end
