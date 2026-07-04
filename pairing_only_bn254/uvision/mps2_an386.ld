/* MPS2-AN386 (Cortex-M4): 4MB flash, 4MB SRAM */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x00000000, LENGTH = 4M
    SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 4M
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
