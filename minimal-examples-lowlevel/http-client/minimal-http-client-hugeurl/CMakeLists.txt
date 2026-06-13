project(lws-minimal-http-client-hugeurl C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-hugeurl)
set(SRCS minimal-http-client-hugeurl.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(PORT_HC_HUGE_SRV "10040")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_HC_HUGE_SRV "10041 + ($ENV{SAI_INSTANCE_IDX} * 1000)")
	endif()

	if (NOT WIN32 AND LWS_WITH_SERVER AND LWS_WITH_TLS)
		add_test(NAME st_hc_huge_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
					hc_huge_srv
					$<TARGET_FILE:test-server>
					-r ${CMAKE_BINARY_DIR}/share/libwebsockets-test-server/
					-s --port ${PORT_HC_HUGE_SRV} )
		add_test(NAME ki_hc_huge_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hc_huge_srv
					$<TARGET_FILE_NAME:test-server> --port ${PORT_HC_HUGE_SRV})

		set_tests_properties(st_hc_huge_srv PROPERTIES
							 WORKING_DIRECTORY .
							 FIXTURES_SETUP hc_huge_srv
							 TIMEOUT 800)
		set_tests_properties(ki_hc_huge_srv PROPERTIES
							 FIXTURES_CLEANUP hc_huge_srv)

		#
		# creates a fixture res_hchugeurlw to get a lease on the
		# server resources
		#
		sai_resource(warmcat_conns 1 40 hchugeurlw)
	
		add_test(NAME http-client-hugeurl-warmcat COMMAND lws-minimal-http-client-hugeurl -l --server localhost -p ${PORT_HC_HUGE_SRV})
		add_test(NAME http-client-hugeurl-warmcat-h1 COMMAND lws-minimal-http-client-hugeurl -l --server localhost -p ${PORT_HC_HUGE_SRV} --h1)
		set_tests_properties(http-client-hugeurl-warmcat
				     http-client-hugeurl-warmcat-h1
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-client/minimal-http-client-hugeurl
				     FIXTURES_REQUIRED "hc_huge_srv"
				     TIMEOUT 60)
		if (DEFINED ENV{SAI_OVN})
			set_tests_properties(http-client-hugeurl-warmcat
					     http-client-hugeurl-warmcat-h1
					     PROPERTIES
						FIXTURES_REQUIRED "res_hchugeurlw;hc_huge_srv")	
		endif()

	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
