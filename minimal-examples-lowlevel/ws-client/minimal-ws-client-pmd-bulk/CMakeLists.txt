project(lws-minimal-ws-client-pmd-bulk C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-ws-client-pmd-bulk)
set(SRCS minimal-ws-client-pmd-bulk.c)

set(requirements 1)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
#require_lws_config(LWS_WITHOUT_EXTENSIONS 0 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# For the ctests we also need the matching server example built, and
	# the pmd extension support compiled in
	#

	set(test_requirements 1)
	require_lws_config(LWS_WITH_SERVER 1 test_requirements)
	require_lws_config(LWS_WITHOUT_EXTENSIONS 0 test_requirements)

	if (test_requirements AND NOT WIN32)

		#
		# Get ports that are unique on this build machine, so parallel
		# CI instances on the same host don't tread on each other
		#

		lws_get_free_port(PORT_PMDBLK_FRAG)
		lws_get_free_port(PORT_PMDBLK_BLOB)

		#
		# Fixture: server sending compressible data in fragments
		#

		add_test(NAME st_pmdblk_frag COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				pmdblk_frag
				$<TARGET_FILE:lws-minimal-ws-server-pmd-bulk>
				--port ${PORT_PMDBLK_FRAG} -c)
		add_test(NAME ki_pmdblk_frag COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				pmdblk_frag
				$<TARGET_FILE_NAME:lws-minimal-ws-server-pmd-bulk>)

		set_tests_properties(st_pmdblk_frag PROPERTIES
					     WORKING_DIRECTORY .
					     FIXTURES_SETUP pmdblk_frag
					     ENVIRONMENT "SAI_LIST_PORT=${PORT_PMDBLK_FRAG}"
					     TIMEOUT 800)
		set_tests_properties(ki_pmdblk_frag PROPERTIES
					     FIXTURES_CLEANUP pmdblk_frag)

		add_test(NAME ws-client-pmd-bulk-frag COMMAND
			$<TARGET_FILE:lws-minimal-ws-client-pmd-bulk>
				--port ${PORT_PMDBLK_FRAG} -c)
		set_tests_properties(ws-client-pmd-bulk-frag PROPERTIES
					     FIXTURES_REQUIRED pmdblk_frag
					     TIMEOUT 60)

		#
		# Fixture: server sending its whole message as one compressed
		# blob.  This is the case from lws issue #3660, where the client
		# was told it had the final fragment while the compressed
		# message was still being inflated
		#

		add_test(NAME st_pmdblk_blob COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
				pmdblk_blob
				$<TARGET_FILE:lws-minimal-ws-server-pmd-bulk>
				--port ${PORT_PMDBLK_BLOB} -c -b)
		add_test(NAME ki_pmdblk_blob COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
				pmdblk_blob
				$<TARGET_FILE_NAME:lws-minimal-ws-server-pmd-bulk>)

		set_tests_properties(st_pmdblk_blob PROPERTIES
					     WORKING_DIRECTORY .
					     FIXTURES_SETUP pmdblk_blob
					     ENVIRONMENT "SAI_LIST_PORT=${PORT_PMDBLK_BLOB}"
					     TIMEOUT 800)
		set_tests_properties(ki_pmdblk_blob PROPERTIES
					     FIXTURES_CLEANUP pmdblk_blob)

		add_test(NAME ws-client-pmd-bulk-blob COMMAND
			$<TARGET_FILE:lws-minimal-ws-client-pmd-bulk>
				--port ${PORT_PMDBLK_BLOB} -c)
		set_tests_properties(ws-client-pmd-bulk-blob PROPERTIES
					     FIXTURES_REQUIRED pmdblk_blob
					     TIMEOUT 60)
	endif()
endif()
