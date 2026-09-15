project(lws-lhp-browser C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-lhp-browser)

set(requirements 1)
require_lws_config(LWS_WITH_UPNG 1 requirements)
require_lws_config(LWS_WITH_LHP 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)

#
# The native window backend lives under plat/.  The CMakeLists.txt in the
# plat dir for this platform decides if the things it needs exist, and
# exports to us how to build and link it; if it is not satisfied, we don't
# build the app at all.  plat/unix is X11; native mac / win32 backends can
# be added under plat/ with the same shape later.
#

if (WIN32)
	set(PLAT_DIR plat/win32)
elseif (APPLE)
	set(PLAT_DIR plat/mac)
else()
	set(PLAT_DIR plat/unix)
endif()

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${PLAT_DIR}/CMakeLists.txt)
	add_subdirectory(${PLAT_DIR})
else()
	message(STATUS "lhp-browser: no ${PLAT_DIR} window backend in this tree yet")
endif()

if (requirements AND LHP_BROWSER_PLAT_OK)

	add_executable(${SAMP} main.c ${LHP_BROWSER_PLAT_SRC})

	target_compile_definitions(${SAMP} PRIVATE ${LHP_BROWSER_PLAT_DEFS})
	target_include_directories(${SAMP} PRIVATE ${LHP_BROWSER_PLAT_INC})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared
					      ${LIBWEBSOCKETS_DEP_LIBS}
					      ${LHP_BROWSER_PLAT_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets
					      ${LIBWEBSOCKETS_DEP_LIBS}
					      ${LHP_BROWSER_PLAT_LIBS})
	endif()

	#
	# Where a display is available at configure time, a scripted window
	# smoke test: the framebuffer the window presented must be identical
	# to a straight --bmp render of the same document
	#

	if (DEFINED ENV{DISPLAY} AND NOT WIN32)
		add_test(NAME lhp-browser-window-shot
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/test.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/window-shot.bmp
				-P ${CMAKE_CURRENT_SOURCE_DIR}/shot-test.cmake)
	endif()
else()
	if (requirements)
		message(STATUS "lhp-browser: skipping, no usable window backend for this platform")
	endif()
endif()
