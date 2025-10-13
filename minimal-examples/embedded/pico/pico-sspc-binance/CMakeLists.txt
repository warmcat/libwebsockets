# pico-sspc-binance demo
#
# connects a headless, networkless pico to binance over UART transport, using
#  lws-minimal-secure-streams-custom-proxy-transport minimal example on PC
#
# Symlink or git submodule ./libwebsockets/ to main lws
# Build the whole thing with something like
#
# cmake .. -DLWS_ONLY_SSPC=1 -DPICO_SDK_PATH=../../pico-sdk
#
# proxy has to support LWS_ROLE_WS=1 and LWS_WITHOUT_EXTENSIONS=0
# to work with binance itself

cmake_minimum_required(VERSION 3.10)

# initialize the SDK based on PICO_SDK_PATH
# note: this must happen before project()
include(pico_sdk_import.cmake)

project(pico-sspc-binance)
pico_sdk_init()

set(LWS_WITH_SSL 0)
set(LWS_WITH_TLS 0)
set(LWS_WITH_SHARED 0)
set(LWS_PLAT_BAREMETAL 1)
set(LWS_WITH_NETWORK 0)
set(LWS_ONLY_SSPC 1) # remove everything except SSPC pieces from library build
# build lws as part of this
add_subdirectory(libwebsockets)
add_executable(pico-sspc-binance
    main.c
    system.c
    helpers.c
    transport-serial.c
    binance-ss.c
    get-ss.c
)

target_compile_definitions(pico-sspc-binance PUBLIC
				PICO_STACK_SIZE=0x2000
				LWS_SS_USE_SSPC)


# make sure we can include libwebsockets.h from the lws build
target_include_directories(pico-sspc-binance PRIVATE
	# lws_config.h generated into here
	${PROJECT_BINARY_DIR}/libwebsockets
	# source includes will do for everything else
	${PROJECT_SOURCE_DIR}/libwebsockets/include )

target_link_libraries(pico-sspc-binance
			pico_stdlib
			hardware_uart
			websockets)

# logs on USB console /dev/ttyACM
pico_enable_stdio_usb(pico-sspc-binance 1)
# UART0 will be the sspc transport, don't put the console on it
pico_enable_stdio_uart(pico-sspc-binance 0)

pico_add_extra_outputs(pico-sspc-binance)
