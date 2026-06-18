cmake_minimum_required(VERSION 3.14)
project(groth16_verifier_arm C ASM)

# --- Platform check ---
if(NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    message(FATAL_ERROR "This project requires ARM cross-compilation.\n"
        "Use: cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-arm-none-eabi.cmake")
endif()

execute_process(
    COMMAND ${CMAKE_C_COMPILER} -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -print-file-name=include
    OUTPUT_VARIABLE GCC_BUILTIN_INCLUDE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# --- RELIC Configuration for Ethereum BN254 (ARM, assembly backend) ---
set(WSIZE   32      CACHE STRING "" FORCE)
set(RAND    "HASHD" CACHE STRING "" FORCE)
set(SEED    ""      CACHE STRING "" FORCE)
set(SHLIB   OFF     CACHE BOOL "" FORCE)
set(STBIN   OFF     CACHE BOOL "" FORCE)
set(TIMER   "NONE"  CACHE STRING "" FORCE)
set(CHECK   OFF     CACHE BOOL "" FORCE)
set(VERBS   OFF     CACHE BOOL "" FORCE)
set(ALLOC   "AUTO"  CACHE STRING "" FORCE)
set(MULTI   "OFF"   CACHE STRING "" FORCE)
set(BENCH   0       CACHE INTEGER "" FORCE)
set(TESTS   0       CACHE INTEGER "" FORCE)

set(WITH "BN;DV;FP;FPX;EP;EPX;PP;MD" CACHE STRING "" FORCE)

set(EP_PRECO  OFF  CACHE BOOL "" FORCE)
set(EP_CTMAP  OFF  CACHE BOOL "" FORCE)

set(FP_PRIME  254   CACHE STRING "" FORCE)
set(FP_QNRES  OFF  CACHE BOOL "" FORCE)
set(FP_METHD  "INTEG;INTEG;INTEG;MONTY;JMPDS;JMPDS;SLIDE" CACHE STRING "" FORCE)
set(FPX_METHD "INTEG;INTEG;LAZYR" CACHE STRING "" FORCE)
set(PP_METHD  "LAZYR;OATEP" CACHE STRING "" FORCE)

# ARM assembly backend for Ethereum BN254 field arithmetic
# Override with -DFORCE_ARITH=easy to use generic C instead
if(DEFINED FORCE_ARITH)
    set(ARITH "${FORCE_ARITH}" CACHE STRING "" FORCE)
else()
    set(ARITH "arm-asm-254e" CACHE STRING "" FORCE)
endif()

set(CFLAGS "-mcpu=cortex-m4 -mthumb -mfloat-abi=soft -ffreestanding -O2 -nostdinc -isystem ${CMAKE_SOURCE_DIR}/bare_metal/include -isystem ${GCC_BUILTIN_INCLUDE}" CACHE STRING "" FORCE)

add_subdirectory(lib/relic)

# --- Verifier library ---
add_library(groth16_verifier STATIC
    src/point_decode.c
    src/crypto_init.c
    src/groth16_verifier.c
)
target_include_directories(groth16_verifier PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/lib/relic/include
    ${CMAKE_SOURCE_DIR}/lib/relic/include
)
target_compile_options(groth16_verifier PRIVATE
    -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -ffreestanding -O2
    -nostdinc
    "SHELL:-isystem ${CMAKE_SOURCE_DIR}/bare_metal/include"
    "SHELL:-isystem ${GCC_BUILTIN_INCLUDE}"
)
target_link_libraries(groth16_verifier PUBLIC relic_s)

# --- Board / linker script selection ---
# Default: netduinoplus2 (STM32F405, 1MB flash, 128KB SRAM)
# Override with: cmake .. -DBOARD=mps2-an386 (4MB flash, 4MB SRAM)
if(NOT DEFINED BOARD)
    set(BOARD "netduinoplus2")
endif()

if(BOARD STREQUAL "mps2-an386")
    set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/bare_metal/mps2_an386.ld)
else()
    set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/bare_metal/stm32f405.ld)
endif()
message(STATUS "Board: ${BOARD}  Linker script: ${LINKER_SCRIPT}")

execute_process(
    COMMAND ${CMAKE_C_COMPILER} -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -print-libgcc-file-name
    OUTPUT_VARIABLE LIBGCC_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# --- Helper macro for ARM bare-metal executables ---
macro(add_arm_executable NAME)
    add_executable(${NAME} ${ARGN} bare_metal/startup.c)
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/test
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/lib/relic/include
        ${CMAKE_SOURCE_DIR}/lib/relic/include
    )
    target_compile_options(${NAME} PRIVATE
        -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -ffreestanding -O2
        -nostdinc
        "SHELL:-isystem ${CMAKE_SOURCE_DIR}/bare_metal/include"
        "SHELL:-isystem ${GCC_BUILTIN_INCLUDE}"
    )
    set_target_properties(${NAME} PROPERTIES LINK_DEPENDS ${LINKER_SCRIPT})
    target_link_options(${NAME} PRIVATE
        -T${LINKER_SCRIPT}
        -nostartfiles -nostdlib
    )
    set_property(TARGET ${NAME} PROPERTY LINK_LIBRARIES
        -Wl,--start-group
        $<TARGET_FILE:groth16_verifier>
        $<TARGET_FILE:relic_s>
        ${LIBGCC_PATH}
        -Wl,--end-group
    )
    add_dependencies(${NAME} groth16_verifier relic_s)
endmacro()

# --- Test (ARM bare-metal, runs under QEMU) ---
add_arm_executable(test_verifier_arm test/test_verifier_arm.c)

# --- Benchmark (ARM bare-metal, measures SysTick cycles) ---
add_arm_executable(bench_verifier_arm test/bench_verifier_arm.c)

# --- Pairing-only benchmark (isolates pp_map_sim_k12) ---
# Override iteration count with: cmake .. -DPAIRING_ITERS=11
if(NOT DEFINED PAIRING_ITERS)
    set(PAIRING_ITERS 1)
endif()
add_arm_executable(bench_pairing_arm test/bench_pairing_arm.c)
target_compile_definitions(bench_pairing_arm PRIVATE PAIRING_ITERS=${PAIRING_ITERS})

# --- Cross-validation (ARM bare-metal, dumps intermediate values) ---
add_arm_executable(cross_validate_arm test/cross_validate.c)
