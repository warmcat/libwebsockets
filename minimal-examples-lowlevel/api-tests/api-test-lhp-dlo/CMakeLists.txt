project(lws-api-test-lhp-dlo C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-lhp-dlo)
set(SRCS main.c )

set(requirements 1)
require_lws_config(LWS_WITH_UPNG 1 requirements)
require_lws_config(LWS_WITH_LHP 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# Layout regression tests: each cases/NN-name.html is laid out and the
	# DLO tree dump compared with cases/NN-name.dlo (see lhp-dlo-case.cmake)
	#

	if (LWS_WITH_FILE_OPS AND NOT WIN32)
		file(GLOB LHP_CASES ${CMAKE_CURRENT_SOURCE_DIR}/cases/*.html)
		foreach(C ${LHP_CASES})
			get_filename_component(CN ${C} NAME_WE)
			add_test(NAME api-test-lhp-dlo-${CN}
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${C}
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/${CN}.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/${CN}.dlo
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endforeach()
		add_test(NAME api-test-lhp-dlo-test-html
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/test.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/test.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/test.dlo
				-DW=1600 -DH=2000
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)

		# captured real-world pages, with their network assets made
		# unreachable so the layout is the same every run
		foreach(VEC lobsters-1/lobsters slashdot-1/slashdot-1)
			get_filename_component(VN ${VEC} NAME)
			add_test(NAME api-test-lhp-dlo-vector-${VN}
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/vectors/${VEC}.html
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/vectors/${VEC}.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/${VN}.dlo
					-DW=800 -DH=1200 -DLOCALIZE=1
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endforeach()
	endif()
endif()
