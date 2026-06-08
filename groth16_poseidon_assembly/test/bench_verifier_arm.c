#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "groth16_verifier.h"
#include "test_vectors.h"

/* SysTick registers (standard Cortex-M, same on real HW and QEMU) */
#define SYST_CSR  (*(volatile uint32_t *)0xE000E010)
#define SYST_RVR  (*(volatile uint32_t *)0xE000E014)
#define SYST_CVR  (*(volatile uint32_t *)0xE000E018)

#define SYSTICK_RELOAD 0x00FFFFFF  /* 24-bit max = 16777215 */

volatile uint32_t systick_overflow_count;

void SysTick_Handler(void) {
    systick_overflow_count++;
}

static void systick_init(void) {
    SYST_RVR = SYSTICK_RELOAD;
    SYST_CVR = 0;
    /* CLKSOURCE=processor clock, TICKINT=enable, ENABLE=on */
    SYST_CSR = (1 << 2) | (1 << 1) | (1 << 0);
}

static void systick_reset(void) {
    SYST_CVR = 0;
    systick_overflow_count = 0;
}

static uint32_t systick_elapsed(void) {
    uint32_t cvr = SYST_CVR;
    uint32_t overflows = systick_overflow_count;
    uint32_t partial = SYSTICK_RELOAD - cvr;
    return overflows * (SYSTICK_RELOAD + 1) + partial;
}

#define NUM_ITERS 3

int main(void) {
    if (groth16_init() != 0) {
        printf("FAIL: groth16_init\n");
        return 1;
    }

    /* Sanity check before benchmarking */
    int result = groth16_verify(TEST_PROOF, 256, TEST_PUBLIC_INPUT, 32);
    if (result != 1) {
        printf("FAIL: proof doesn't verify (result=%d)\n", result);
        return 1;
    }

    printf("=== Groth16 Verifier Benchmark (ARM Cortex-M4) ===\n");
    printf("SysTick reload: 0x%X (%u)\n", SYSTICK_RELOAD, SYSTICK_RELOAD);
    printf("Iterations: %d\n\n", NUM_ITERS);

    systick_init();

    uint32_t ticks[NUM_ITERS];

    for (int i = 0; i < NUM_ITERS; i++) {
        systick_reset();

        result = groth16_verify(TEST_PROOF, 256, TEST_PUBLIC_INPUT, 32);

        ticks[i] = systick_elapsed();

        printf("  iter %d: %u ticks (%u overflows, result=%d)\n",
               i, ticks[i], systick_overflow_count, result);
    }

    /* Compute average */
    uint32_t total = 0;
    for (int i = 0; i < NUM_ITERS; i++) total += ticks[i];
    uint32_t avg = total / NUM_ITERS;

    printf("\n--- Results ---\n");
    printf("Average: %u ticks\n", avg);

    /* Estimated wall-clock on real hardware */
    uint32_t ms_168 = avg / 168000;
    uint32_t ms_100 = avg / 100000;
    printf("At 168 MHz (STM32F407): ~%u ms\n", ms_168);
    printf("At 100 MHz:             ~%u ms\n", ms_100);

    groth16_cleanup();
    return 0;
}
