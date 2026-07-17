cmake_minimum_required(VERSION 3.14)
project(groth16_verifier C)

# One-way dependency: device_verifier_bn254 owns everything the device ships —
# the trimmed RELIC tree, the RELIC-independent fr.c/poseidon.c hash stack,
# and the generated VK/vector headers. This project is the host-side test
# harness layered on top of it; nothing here is referenced back by the
# device build.
set(POB ${CMAKE_SOURCE_DIR}/../device_verifier_bn254)
set(RELIC_DIR ${POB}/lib/relic)

# --- RELIC Configuration for Ethereum BN254 ---
set(WSIZE   64    CACHE STRING "" FORCE)
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
set(FP_QNRES  OFF  CACHE BOOL "" FORCE)
set(FP_METHD  "INTEG;INTEG;INTEG;MONTY;JMPDS;JMPDS;SLIDE" CACHE STRING "" FORCE)
set(FPX_METHD "INTEG;INTEG;LAZYR" CACHE STRING "" FORCE)
set(PP_METHD  "LAZYR;OATEP" CACHE STRING "" FORCE)

set(ARITH "easy" CACHE STRING "" FORCE)
set(CFLAGS "-O2" CACHE STRING "" FORCE)

# Per-function/data sections + dead-strip (same as device_verifier_bn254) so the
# linked image only contains the verify path.
add_compile_options(-ffunction-sections -fdata-sections)
if(APPLE)
    add_link_options(-Wl,-dead_strip)
else()
    add_link_options(-Wl,--gc-sections)
endif()

add_subdirectory(${RELIC_DIR} relic_build)

# --- Verifier library ---
add_library(groth16_verifier STATIC
    src/point_decode.c
    src/crypto_init.c
    src/groth16_verifier.c
)
target_include_directories(groth16_verifier PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${POB}/include
    ${CMAKE_BINARY_DIR}/relic_build/include
    ${RELIC_DIR}/include
)
target_link_libraries(groth16_verifier PUBLIC relic_s)

# --- Main verifier ---
add_executable(groth16_verifier_main src/main.c)
target_include_directories(groth16_verifier_main PRIVATE ${POB}/test)
target_link_libraries(groth16_verifier_main PRIVATE groth16_verifier)

# --- Test ---
add_executable(test_verifier test/test_verifier.c)
target_link_libraries(test_verifier PRIVATE groth16_verifier)

# --- Cross-validation ---
add_executable(cross_validate test/cross_validate.c)
target_include_directories(cross_validate PRIVATE ${POB}/test)
target_link_libraries(cross_validate PRIVATE groth16_verifier)

# --- Profile ---
add_executable(profile_verify test/profile_verify.c)
target_include_directories(profile_verify PRIVATE ${POB}/test)
target_link_libraries(profile_verify PRIVATE groth16_verifier)

# --- Fr backend self-test (standalone, no RELIC) ---
add_executable(fr_selftest ${POB}/src/fr.c test/fr_selftest.c)
target_include_directories(fr_selftest PRIVATE ${POB}/include)

# --- Poseidon cross-validation vs arkworks prover (standalone, no RELIC) ---
add_executable(poseidon_cross_validate
    ${POB}/src/fr.c
    ${POB}/src/poseidon.c
    test/poseidon_cross_validate.c
)
target_include_directories(poseidon_cross_validate PRIVATE ${POB}/include)

# --- Byte-sponge cross-validation vs dump_sponge_vectors (standalone, no RELIC) ---
add_executable(poseidon_sponge_cross_validate
    ${POB}/src/fr.c
    ${POB}/src/poseidon.c
    test/poseidon_sponge_cross_validate.c
)
target_include_directories(poseidon_sponge_cross_validate PRIVATE ${POB}/include)

# --- Clear-signing E2E (two-hash: on-chip Poseidon + 2-input Groth16) ---
add_executable(clear_signing_verifier
    src/clear_signing_main.c
    ${POB}/src/fr.c
    ${POB}/src/poseidon.c
)
target_include_directories(clear_signing_verifier PRIVATE ${POB}/test)
target_link_libraries(clear_signing_verifier PRIVATE groth16_verifier)

# --- Poseidon-preimage CLI (file-driven: VK/proof/public-input from argv) ---
add_executable(poseidon_preimage_cli src/poseidon_preimage_cli.c)
target_link_libraries(poseidon_preimage_cli PRIVATE groth16_verifier)

# --- Clear-signing CLI (file-driven: VK/proof/calldata/text from argv) ---
add_executable(clear_signing_cli
    src/clear_signing_cli.c
    ${POB}/src/fr.c
    ${POB}/src/poseidon.c
)
target_link_libraries(clear_signing_cli PRIVATE groth16_verifier)

# --- Clear-signing profile (per-phase host timing, step 6) ---
add_executable(clear_signing_profile
    test/clear_signing_profile.c
    ${POB}/src/fr.c
    ${POB}/src/poseidon.c
)
target_include_directories(clear_signing_profile PRIVATE ${POB}/test)
target_link_libraries(clear_signing_profile PRIVATE groth16_verifier)
