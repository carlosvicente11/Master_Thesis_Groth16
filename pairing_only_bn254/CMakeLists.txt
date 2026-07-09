cmake_minimum_required(VERSION 3.14)
project(pairing_only_bn254 C)

# Two build modes:
#   Host (default):      cmake -S . -B build
#   Cortex-M4 bare-metal: cmake -S . -B build_m4 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-none-eabi.cmake
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    set(M4_BUILD TRUE)
else()
    set(M4_BUILD FALSE)
endif()

# --- RELIC Configuration for Ethereum BN254 ---
if(M4_BUILD)
    # 32-bit limbs (Cortex-M4 word width). Verified on host 2026-07-02:
    # Correctness PASS, ~4.0 ms/multi-pairing vs ~1.27 ms at 64-bit.
    set(WSIZE 32 CACHE STRING "" FORCE)
    set(SEED  "" CACHE STRING "" FORCE)
    # RELIC auto-detects ARCH=ARM from the toolchain, but the tree carries no
    # relic_arch_arm.c (arch/ has a64/x64/none only) -> arch_lzcnt undefined.
    # NONE is the portable-C arch backend and is what the uVision conf uses.
    set(ARCH  "NONE" CACHE STRING "" FORCE)
else()
    set(WSIZE 64 CACHE STRING "" FORCE)
endif()
# CALL = randomness via user callback; none is registered because the verify
# path is fully deterministic. Bare-metal safe (no /dev/urandom on the M4).
set(RAND    "CALL" CACHE STRING "" FORCE)
set(SHLIB   OFF   CACHE BOOL "" FORCE)
set(STBIN   OFF   CACHE BOOL "" FORCE)
set(TIMER   "NONE" CACHE STRING "" FORCE)
set(CHECK   OFF   CACHE BOOL "" FORCE)
set(VERBS   OFF   CACHE BOOL "" FORCE)
set(ALLOC   "AUTO" CACHE STRING "" FORCE)
set(MULTI   "OFF"  CACHE STRING "" FORCE)
set(BENCH   0     CACHE INTEGER "" FORCE)
set(TESTS   0     CACHE INTEGER "" FORCE)

set(WITH "BN;DV;FP;FPX;EP;EPX;PP" CACHE STRING "" FORCE)

set(EP_PRECO  OFF  CACHE BOOL "" FORCE)
set(EP_CTMAP  OFF  CACHE BOOL "" FORCE)

set(FP_PRIME  254   CACHE STRING "" FORCE)
# FP_QNRES=ON is ~19% faster but switches the Fp12 tower away from the Ethereum
# convention (xi = 9+u), breaking compatibility with externally generated
# proof/VK vectors (correctness check fails). Keep OFF.
set(FP_QNRES  OFF  CACHE BOOL "" FORCE)
set(FP_METHD  "INTEG;INTEG;INTEG;MONTY;JMPDS;JMPDS;SLIDE" CACHE STRING "" FORCE)
set(FPX_METHD "INTEG;INTEG;LAZYR" CACHE STRING "" FORCE)
set(PP_METHD  "LAZYR;OATEP" CACHE STRING "" FORCE)

set(ARITH "easy" CACHE STRING "" FORCE)

if(M4_BUILD)
    execute_process(
        COMMAND ${CMAKE_C_COMPILER} -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -print-file-name=include
        OUTPUT_VARIABLE GCC_BUILTIN_INCLUDE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(M4_FLAGS
        -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -ffreestanding -O2
        -ffunction-sections -fdata-sections
        -nostdinc
        "SHELL:-isystem ${CMAKE_SOURCE_DIR}/uvision/include"
        "SHELL:-isystem ${GCC_BUILTIN_INCLUDE}"
    )
    set(CFLAGS "-mcpu=cortex-m4 -mthumb -mfloat-abi=soft -ffreestanding -O2 -ffunction-sections -fdata-sections -nostdinc -isystem ${CMAKE_SOURCE_DIR}/uvision/include -isystem ${GCC_BUILTIN_INCLUDE}" CACHE STRING "" FORCE)
else()
    set(CFLAGS "-O2" CACHE STRING "" FORCE)
endif()

# Per-function/data sections + dead-strip so the linker drops everything the
# pairing path doesn't reference (dead-strip on macOS, --gc-sections on
# GNU/armclang). This is what keeps the linked image minimal: RELIC bundles many
# functions per translation unit, so without this the whole object is pulled in.
# Applied globally here (before add_subdirectory) so it covers RELIC too.
add_compile_options(-ffunction-sections -fdata-sections)
if(APPLE AND NOT M4_BUILD)
    add_link_options(-Wl,-dead_strip)
else()
    add_link_options(-Wl,--gc-sections)
endif()

add_subdirectory(lib/relic)

# --- Pairing library (BN254 multi-pairing) ---
# multi_pairing.c is host-only (clock_gettime); the M4 build times pp_map_sim_k12
# itself via SysTick in uvision/main_m4.c.
set(PAIRING_SRC src/point_decode.c src/crypto_init.c)
if(NOT M4_BUILD)
    list(APPEND PAIRING_SRC src/multi_pairing.c)
endif()
add_library(pairing STATIC ${PAIRING_SRC})
target_include_directories(pairing PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/lib/relic/include
    ${CMAKE_SOURCE_DIR}/lib/relic/include
)
if(M4_BUILD)
    target_compile_options(pairing PRIVATE ${M4_FLAGS})
endif()
target_link_libraries(pairing PUBLIC relic_s)

if(NOT M4_BUILD)
    # --- Multi-pairing benchmark executable (host) ---
    add_executable(multi_pairing_bench src/multi_pairing_main.c)
    target_include_directories(multi_pairing_bench PRIVATE ${CMAKE_SOURCE_DIR}/test)
    target_link_libraries(multi_pairing_bench PRIVATE pairing)
else()
    # --- Bare-metal benchmark (Keil uVision simulator / QEMU / real HW) ---
    # BOARD=mps2-an386 (QEMU, 4MB flash/SRAM) or stm32f405 (1MB flash, 128KB SRAM)
    if(NOT DEFINED BOARD)
        set(BOARD "mps2-an386")
    endif()
    if(BOARD STREQUAL "stm32f405")
        set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/uvision/stm32f405.ld)
    else()
        set(LINKER_SCRIPT ${CMAKE_SOURCE_DIR}/uvision/mps2_an386.ld)
    endif()
    message(STATUS "Board: ${BOARD}  Linker script: ${LINKER_SCRIPT}")

    execute_process(
        COMMAND ${CMAKE_C_COMPILER} -mcpu=cortex-m4 -mthumb -mfloat-abi=soft -print-libgcc-file-name
        OUTPUT_VARIABLE LIBGCC_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(NOT DEFINED PAIRING_ITERS)
        set(PAIRING_ITERS 3)
    endif()

    add_executable(multi_pairing_m4 uvision/main_m4.c uvision/startup.c)
    target_include_directories(multi_pairing_m4 PRIVATE
        ${CMAKE_SOURCE_DIR}/test
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/lib/relic/include
        ${CMAKE_SOURCE_DIR}/lib/relic/include
    )
    target_compile_options(multi_pairing_m4 PRIVATE ${M4_FLAGS})
    target_compile_definitions(multi_pairing_m4 PRIVATE PAIRING_ITERS=${PAIRING_ITERS})
    set_target_properties(multi_pairing_m4 PROPERTIES LINK_DEPENDS ${LINKER_SCRIPT})
    target_link_options(multi_pairing_m4 PRIVATE
        -T${LINKER_SCRIPT}
        -nostartfiles -nostdlib
        -Wl,--gc-sections
        -Wl,-Map=multi_pairing_m4.map
    )
    set_property(TARGET multi_pairing_m4 PROPERTY LINK_LIBRARIES
        -Wl,--start-group
        $<TARGET_FILE:pairing>
        $<TARGET_FILE:relic_s>
        ${LIBGCC_PATH}
        -Wl,--end-group
    )
    add_dependencies(multi_pairing_m4 pairing relic_s)

    # --- Bare-metal single-pairing micro-benchmark ---
    # One pp_map_k12 (1 Miller loop + 1 final exp), bilinearity-checked;
    # isolates the pairing for measuring low-level arithmetic replacements.
    add_executable(single_pairing_m4 uvision/single_pairing_m4.c uvision/startup.c)
    target_include_directories(single_pairing_m4 PRIVATE
        ${CMAKE_SOURCE_DIR}/test
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/lib/relic/include
        ${CMAKE_SOURCE_DIR}/lib/relic/include
    )
    target_compile_options(single_pairing_m4 PRIVATE ${M4_FLAGS})
    target_compile_definitions(single_pairing_m4 PRIVATE PAIRING_ITERS=${PAIRING_ITERS})
    set_target_properties(single_pairing_m4 PROPERTIES LINK_DEPENDS ${LINKER_SCRIPT})
    target_link_options(single_pairing_m4 PRIVATE
        -T${LINKER_SCRIPT}
        -nostartfiles -nostdlib
        -Wl,--gc-sections
        -Wl,-Map=single_pairing_m4.map
    )
    set_property(TARGET single_pairing_m4 PROPERTY LINK_LIBRARIES
        -Wl,--start-group
        $<TARGET_FILE:pairing>
        $<TARGET_FILE:relic_s>
        ${LIBGCC_PATH}
        -Wl,--end-group
    )
    add_dependencies(single_pairing_m4 pairing relic_s)

    # --- Bare-metal clear-signing verify benchmark (plan step 6) ---
    # Full device flow: 2x on-chip Poseidon (fr.c/poseidon.c from
    # minimal_c_verifier, RELIC-independent) + 2 ep_mul + 3-pair multi-pairing,
    # against the generated clear-signing VK/vector headers.
    set(MCV ${CMAKE_SOURCE_DIR}/../minimal_c_verifier)
    add_executable(clear_signing_m4
        uvision/clear_signing_m4.c
        uvision/startup.c
        ${MCV}/src/fr.c
        ${MCV}/src/poseidon.c
    )
    target_include_directories(clear_signing_m4 PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${MCV}/include
        ${MCV}/test
        ${CMAKE_BINARY_DIR}/lib/relic/include
        ${CMAKE_SOURCE_DIR}/lib/relic/include
    )
    target_compile_options(clear_signing_m4 PRIVATE ${M4_FLAGS})
    set_target_properties(clear_signing_m4 PROPERTIES LINK_DEPENDS ${LINKER_SCRIPT})
    target_link_options(clear_signing_m4 PRIVATE
        -T${LINKER_SCRIPT}
        -nostartfiles -nostdlib
        -Wl,--gc-sections
        -Wl,-Map=clear_signing_m4.map
    )
    set_property(TARGET clear_signing_m4 PROPERTY LINK_LIBRARIES
        -Wl,--start-group
        $<TARGET_FILE:pairing>
        $<TARGET_FILE:relic_s>
        ${LIBGCC_PATH}
        -Wl,--end-group
    )
    add_dependencies(clear_signing_m4 pairing relic_s)
endif()
