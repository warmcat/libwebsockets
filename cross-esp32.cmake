#
# CMake Toolchain file for crosscompiling on ARM.
#
# This can be used when running cmake in the following way:
#  cd build/
#  cmake .. -DCMAKE_TOOLCHAIN_FILE=../cross-arm-linux-gnueabihf.cmake
#

# Target operating system name.
set(CMAKE_SYSTEM_NAME Linux)

# Name of C compiler.
set(CMAKE_C_COMPILER "${CROSS_PATH}/bin/xtensa-esp32-elf-gcc")

SET(CMAKE_C_FLAGS "-nostdlib -Wall -Werror -I${BUILD_DIR_BASE}/include -I${COMPONENT_PATH}/../driver/include -I${COMPONENT_PATH}/../spi_flash/include -I${COMPONENT_PATH}/../nvs_flash/include -I${COMPONENT_PATH}/../tcpip_adapter/include -I${COMPONENT_PATH}/../lwip/include/lwip/posix -I${COMPONENT_PATH}/../lwip/include/lwip -I${COMPONENT_PATH}/../lwip/include/lwip/port -I${COMPONENT_PATH}/../esp32/include/ ${LWS_C_FLAGS} -I${COMPONENT_PATH}/../nvs_flash/test_nvs_host -I${COMPONENT_PATH}/../freertos/include -Os" CACHE STRING "" FORCE)

# Where to look for the target environment. (More paths can be added here)
set(CMAKE_FIND_ROOT_PATH "${CROSS_PATH}")

# Adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Search headers and libraries in the target environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

