/* STM32F405 (Cortex-M4): 1MB flash, 128KB SRAM — matches Netduino Plus 2 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 1M
    SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

_stack_top = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
    .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
    .text       : { *(.text*) *(.rodata*) } > FLASH
    .data       : { *(.data*) } > SRAM AT > FLASH
    .bss        : { __bss_start = .; *(.bss*) *(COMMON) __bss_end = .; } > SRAM
    _end = .;
}
