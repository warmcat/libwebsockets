project(lws-api-test-ota C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-ota)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_OTA 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

#
# The test signs its manifests with ota-test.private.jwk, so lws_ota can only
# accept them if lws was built to trust its public half.  Any other
# LWS_OTA_PUBLIC_JWK_FILE (eg, a real signing key) can't be tested this way.
#
get_filename_component(_ota_jwk_built "${LWS_OTA_PUBLIC_JWK_FILE}" REALPATH)
get_filename_component(_ota_jwk_test
		       "${CMAKE_CURRENT_SOURCE_DIR}/ota-test.public.jwk" REALPATH)
if (NOT _ota_jwk_built STREQUAL _ota_jwk_test OR
    NOT (TARGET websockets_shared OR TARGET websockets))
	# (and it can only be built inside the lws build, see below)
	set(requirements 0)
endif()

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# The fake platform OTA layer needs the private struct lws_ota, as the
	# platform implementations inside lws do: build with the library's own
	# include paths
	#
	if (TARGET websockets_shared)
		set(_ota_lib websockets_shared)
	else()
		set(_ota_lib websockets)
	endif()
	target_include_directories(${SAMP} PRIVATE
		$<TARGET_PROPERTY:${_ota_lib},INCLUDE_DIRECTORIES>)

	lws_get_free_port(PORT_OTA)

	add_test(NAME api-test-ota
		 COMMAND lws-api-test-ota
			 -p ${PORT_OTA}
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-ota
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 120)
endif()
