set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
set(CMAKE_AR arm-none-eabi-ar)
set(CMAKE_RANLIB arm-none-eabi-ranlib)

set(BARE_METAL_INCLUDE "${CMAKE_CURRENT_LIST_DIR}/../bare_metal/include")
get_filename_component(BARE_METAL_INCLUDE "${BARE_METAL_INCLUDE}" ABSOLUTE)

# -nostdinc: disable all default system include paths
# Then add back: our bare-metal stubs (first, takes priority) and GCC builtins (stddef.h, stdarg.h, etc.)
execute_process(
    COMMAND arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -print-file-name=include
    OUTPUT_VARIABLE GCC_BUILTIN_INCLUDE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(CMAKE_C_FLAGS_INIT "-mcpu=cortex-m4 -mthumb -mfloat-abi=soft -ffreestanding -nostdinc -isystem ${BARE_METAL_INCLUDE} -isystem ${GCC_BUILTIN_INCLUDE}")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-nostartfiles -nostdlib")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
