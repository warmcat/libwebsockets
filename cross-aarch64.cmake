#
# CMake Toolchain file for crosscompiling on ARM.
#
# This can be used when running cmake in the following way:
#  cd build/
#  cmake .. -DCMAKE_TOOLCHAIN_FILE=../cross-arm-linux-gnueabihf.cmake
#

# Target operating system name.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Name of C compiler.
set(CMAKE_C_COMPILER "aarch64-linux-gnu-gcc")
set(CMAKE_CXX_COMPILER "aarch64-linux-gnu-g++")

#-nostdlib
SET(CMAKE_C_FLAGS "-DGCC_VER=\"\\\"$(GCC_VER)\\\"\" -DARM64=1 -D__LP64__=1 -Os -g3 -fpie -mstrict-align -DOPTEE_DEV_KIT=../../../optee_os/out/arm-plat-hikey/export-ta_arm64/include -fPIC -ffunction-sections -fdata-sections" CACHE STRING "" FORCE)


# Where to look for the target environment. (More paths can be added here)
set(CMAKE_FIND_ROOT_PATH "/projects/aist-tb/arm64-tc/")

# Adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Search headers and libraries in the target environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)


