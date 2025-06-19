cmake_minimum_required(VERSION 3.10)

set(TOOLCHAIN_PATH "/usr/local/mcuxpressoide-11.4.1_6260/ide/plugins/com.nxp.mcuxpresso.tools.linux_11.4.0.202103011116/tools/bin/arm-none-eabi")

set(CMAKE_C_COMPILER "${TOOLCHAIN_PATH}-gcc")
set(CMAKE_CXX_COMPILER "${TOOLCHAIN_PATH}-g++")

#
# We set up the general build flags first so everything built the same.
#
# We build libwebsockets.a, with LWS_ONLY_SSPC and LWS_PLAT_BAREMETAL etc.
#
# Then we build project/ with LWS_SS_USE_SSPC and link him to our libwebsockets.a


set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_CROSSCOMPILING 1)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -specs=redlib.specs -fno-common -g3 -mcpu=cortex-m33  -ffunction-sections -fdata-sections -ffreestanding -fno-builtin -fmerge-constants -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -D__NEWLIB__ -nostdlib -Xlinker --gc-sections" )
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")
#SET(CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_DIR}/${TARGET_TRIPLET} ${EXTRA_FIND_PATH})
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

project(rt500-hello C)
add_link_options( -ffreestanding -nostdlib -mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mthumb -Xlinker --gc-sections -L ${PROJECT_SOURCE_DIR}/project/Debug -T evkmimxrt595_dev_composite_cdc_vcom_cdc_vcom_bm_Debug.ld )


set(LWS_WITH_SSL	0 CACHE BOOL a)
set(LWS_WITH_TLS	0 CACHE BOOL b)
set(LWS_WITH_SHARED	0 CACHE BOOL c)
set(LWS_PLAT_BAREMETAL	1 CACHE BOOL d)
set(LWS_WITH_NETWORK	0 CACHE BOOL e)
set(LWS_ONLY_SSPC	1 CACHE BOOL f) # remove everything except SSPC pieces from library build

include_directories(${PROJECT_SOURCE_DIR}/project/source)
add_compile_definitions(
				__REDLIB__
				uid_t=int
				gid_t=int
				CPU_MIMXRT595SFFOC
				CPU_MIMXRT595SFFOC_cm33
				_DEBUG=1
				BOOT_HEADER_ENABLE=1
				CPU_MIMXRT595SEVKA=1
				MCUXPRESSO_SDK
				CR_INTEGER_PRINTF
				PRINTF_FLOAT_ENABLE=0
				__MCUXPRESSO
				__USE_CMSIS
				CPU_MIMXRT595SFAWC_cm33
				SERIAL_PORT_TYPE_UART
				ssize_t=long
			)


# build lws as part of this
add_subdirectory(libwebsockets)

add_executable(${PROJECT_NAME}
	project/utilities/fsl_assert.c
	project/utilities/fsl_debug_console.c
	project/usb/phy/usb_phy.c
	project/usb/device/source/lpcip3511/usb_device_lpcip3511.c
	project/usb/device/source/usb_device_ch9.c
	project/usb/device/source/usb_device_dci.c
	project/usb/device/class/cdc/usb_device_cdc_acm.c
	project/usb/device/class/usb_device_class.c
	project/startup/startup_mimxrt595s_cm33.c
	project/source/sspc/binance-ss.c
	project/source/sspc/get-ss.c
	project/source/sspc/helpers.c
	project/source/sspc/main.c
	project/source/sspc/system.c
	project/source/sspc/transport-serial.c
	project/source/composite.c
	project/source/semihost_hardfault.c
	project/source/usb_device_descriptor.c
	project/source/virtual_com.c
	project/flash_config/flash_config.c
	project/drivers/fsl_cache.c
	project/drivers/fsl_clock.c
	project/drivers/fsl_common.c
	project/drivers/fsl_common_arm.c
	project/drivers/fsl_flexcomm.c
	project/drivers/fsl_flexspi.c
	project/drivers/fsl_gpio.c
	project/drivers/fsl_iap.c
	project/drivers/fsl_power.c
	project/drivers/fsl_reset.c
	project/drivers/fsl_usart.c
	project/device/system_MIMXRT595S_cm33.c
	project/component/uart/fsl_adapter_usart.c
	project/component/osa/fsl_os_abstraction_bm.c
	project/component/lists/fsl_component_generic_list.c
	project/board/board.c
	project/board/clock_config.c
	project/board/pin_mux.c
	)


target_compile_definitions(${PROJECT_NAME} PUBLIC
				__REDLIB__
				uid_t=int
				gid_t=int
				STANDALONE=1
				CPU_MIMXRT595SFFOC
				CPU_MIMXRT595SFFOC_cm33
				_DEBUG=1
				BOOT_HEADER_ENABLE=1
				FSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1
				USB_STACK_BM
				CPU_MIMXRT595SEVKA=1
				USB_STACK_USE_DEDICATED_RAM=1
				FSL_OSA_BM_TASK_ENABLE=0
				FSL_OSA_BM_TIMER_CONFIG=0
				SDK_DEBUGCONSOLE=1
				MCUXPRESSO_SDK
				CR_INTEGER_PRINTF
				PRINTF_FLOAT_ENABLE=0
				__MCUXPRESSO
				__USE_CMSIS
				CPU_MIMXRT595SFAWC_cm33
				SERIAL_PORT_TYPE_UART
				LWS_SS_USE_SSPC)

target_include_directories(${PROJECT_NAME} PRIVATE
				project/board
				project/devices/MIMXRT595S/drivers
				project/devices/MIMXRT595S/
				project/CMSIS/Core/Include
				project/devices/MIMXRT595S/utilities/debug_console
				project/component/lists
				project/component/serial_manager
				project/component/uart
				project/component/osa
				project/CMSIS
				project/device
				project/drivers
				project/usb/include
				project/usb/phy
				project/usb/device/source
				project/usb/device/class
				project/usb/device/class/cdc
				project/usb/device/source/lpcip3511
				project/usb/device/include
				project/source
				project/source/sspc
				project/utilities
				# lws_config.h generated into here
				${PROJECT_BINARY_DIR}/libwebsockets
				# source includes will do for everything else
				libwebsockets/include )

set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".axf")
target_link_libraries(${PROJECT_NAME} websockets)


