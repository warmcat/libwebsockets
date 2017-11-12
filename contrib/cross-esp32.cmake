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
set(CMAKE_C_COMPILER	"${CROSS_PATH}/bin/xtensa-esp32-elf-gcc${EXECUTABLE_EXT}")
set(CMAKE_AR		"${CROSS_PATH}/bin/xtensa-esp32-elf-ar${EXECUTABLE_EXT}")
set(CMAKE_RANLIB	"${CROSS_PATH}/bin/xtensa-esp32-elf-ranlib${EXECUTABLE_EXT}")
set(CMAKE_LINKER	"${CROSS_PATH}/bin/xtensa-esp32-elf-ld${EXECUTABLE_EXT}")

SET(CMAKE_C_FLAGS "-nostdlib -Wall -Werror \
	-I${BUILD_DIR_BASE}/include \
	-I${IDF_PATH}/components/mdns/include \
	-I${IDF_PATH}/components/heap/include \
	-I${IDF_PATH}/components/driver/include \
	-I${IDF_PATH}/components/spi_flash/include \
	-I${IDF_PATH}/components/nvs_flash/include \
	-I${IDF_PATH}/components/tcpip_adapter/include \
	-I${IDF_PATH}/components/lwip/include/lwip/posix \
	-I${IDF_PATH}/components/lwip/include/lwip \
	-I${IDF_PATH}/components/lwip/include/lwip/port \
	-I${IDF_PATH}/components/esp32/include/ \
	-I${IDF_PATH}/components/bootloader_support/include/ \
	-I${IDF_PATH}/components/app_update/include/ \
	-I$(IDF_PATH)/components/soc/esp32/include/ \
	-I$(IDF_PATH)/components/soc/include/ \
	-I$(IDF_PATH)/components/vfs/include/ \
	${LWS_C_FLAGS} -Os \
	-I${IDF_PATH}/components/nvs_flash/test_nvs_host \
	-I${IDF_PATH}/components/freertos/include" CACHE STRING "" FORCE)

# Where to look for the target environment. (More paths can be added here)
set(CMAKE_FIND_ROOT_PATH "${CROSS_PATH}")

# Adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Search headers and libraries in the target environment only.
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

