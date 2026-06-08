cmake_minimum_required(VERSION 3.14)
project(groth16_verifier C)

# --- RELIC Configuration for Ethereum BN254 ---
set(WSIZE   64    CACHE STRING "" FORCE)
set(RAND    "UDEV" CACHE STRING "" FORCE)
set(SHLIB   OFF   CACHE BOOL "" FORCE)
set(STBIN   OFF   CACHE BOOL "" FORCE)
set(TIMER   "NONE" CACHE STRING "" FORCE)
set(CHECK   OFF   CACHE BOOL "" FORCE)
set(VERBS   OFF   CACHE BOOL "" FORCE)
set(ALLOC   "AUTO" CACHE STRING "" FORCE)
set(MULTI   "OFF"  CACHE STRING "" FORCE)
set(BENCH   0     CACHE INTEGER "" FORCE)
set(TESTS   0     CACHE INTEGER "" FORCE)

set(WITH "BN;DV;FP;FPX;EP;EPX;PP;MD" CACHE STRING "" FORCE)

set(EP_PRECO  OFF  CACHE BOOL "" FORCE)
set(EP_CTMAP  OFF  CACHE BOOL "" FORCE)

set(FP_PRIME  254   CACHE STRING "" FORCE)
set(FP_QNRES  OFF  CACHE BOOL "" FORCE)
set(FP_METHD  "INTEG;INTEG;INTEG;MONTY;JMPDS;JMPDS;SLIDE" CACHE STRING "" FORCE)
set(FPX_METHD "INTEG;INTEG;LAZYR" CACHE STRING "" FORCE)
set(PP_METHD  "LAZYR;OATEP" CACHE STRING "" FORCE)

set(ARITH "easy" CACHE STRING "" FORCE)
set(CFLAGS "-O2" CACHE STRING "" FORCE)

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
target_link_libraries(groth16_verifier PUBLIC relic_s)

# --- Main verifier ---
add_executable(groth16_verifier_main src/main.c)
target_include_directories(groth16_verifier_main PRIVATE ${CMAKE_SOURCE_DIR}/test)
target_link_libraries(groth16_verifier_main PRIVATE groth16_verifier)

# --- Test ---
add_executable(test_verifier test/test_verifier.c)
target_link_libraries(test_verifier PRIVATE groth16_verifier)

# --- Cross-validation ---
add_executable(cross_validate test/cross_validate.c)
target_link_libraries(cross_validate PRIVATE groth16_verifier)

# --- Profile ---
add_executable(profile_verify test/profile_verify.c)
target_link_libraries(profile_verify PRIVATE groth16_verifier)
