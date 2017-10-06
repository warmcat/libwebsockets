#
# CMake Toolchain file for crosscompiling on 64bit Windows platforms.
#
# This can be used when running cmake in the following way:
#  cd build/
#  cmake .. -DCMAKE_TOOLCHAIN_FILE=../contrib/cross-w64.cmake -DLWS_WITH_SSL=0
#

set(CROSS_PATH /opt/mingw64)

# Target operating system name.
set(CMAKE_SYSTEM_NAME Windows)

# Name of C compiler.
set(CMAKE_C_COMPILER "${CROSS_PATH}/bin/x86_64-w64-mingw32-gcc")
set(CMAKE_CXX_COMPILER "${CROSS_PATH}/bin/x86_64-w64-mingw32-g++")
set(CMAKE_RC_COMPILER "${CROSS_PATH}/bin/x86_64-w64-mingw32-windres")
set(CMAKE_C_FLAGS "-Wno-error")

# Where to look for the target environment. (More paths can be added here)
set(CMAKE_FIND_ROOT_PATH "${CROSS_PATH}")

# Adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Search headers and libraries in the target environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
