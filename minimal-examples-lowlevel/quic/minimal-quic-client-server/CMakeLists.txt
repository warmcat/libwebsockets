project(lws-minimal-quic-client-server C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-quic-client-server)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_QUIC 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	if (LWS_WITH_MINIMAL_EXAMPLES)
		lws_get_free_port(PORT_QCS)
		lws_get_free_port(PORT_QCS_CLIENT)

		find_program(H3SPEC_EXECUTABLE h3spec)
		if (H3SPEC_EXECUTABLE AND LWS_WITH_HTTP3)
			add_test(NAME st_qcs_srv COMMAND
				${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
						qcs_srv
						$<TARGET_FILE:lws-minimal-quic-client-server>
						-s -p ${PORT_QCS} -d 1039 )
			add_test(NAME ki_qcs_srv COMMAND
				${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh qcs_srv
						$<TARGET_FILE_NAME:lws-minimal-quic-client-server> )
			
			set_tests_properties(st_qcs_srv PROPERTIES
							 WORKING_DIRECTORY .
							 FIXTURES_SETUP qcs_srv
							 TIMEOUT 800)
			set_tests_properties(ki_qcs_srv PROPERTIES
							 FIXTURES_CLEANUP qcs_srv)

			add_test(NAME h3spec COMMAND
				${H3SPEC_EXECUTABLE} 127.0.0.1 ${PORT_QCS} -n )
			
			set_tests_properties(h3spec PROPERTIES
					     FIXTURES_REQUIRED "qcs_srv"
					     TIMEOUT 120)
		endif()

		add_test(NAME ${SAMP} COMMAND ${SAMP} --server ${LWS_CTEST_SERVER_RESOLVE} -p ${PORT_QCS_CLIENT})
		set_tests_properties(${SAMP} PROPERTIES
					     WORKING_DIRECTORY .
					     TIMEOUT 20)

		#
		# The same through the reordering relay, with small writes: the
		# handshake's CRYPTO and many small STREAM frames each way reach
		# the peer out of order and must be reassembled.  The relay
		# needs a literal address.
		#
		lws_get_free_port(PORT_QCS_REORDER)
		lws_get_free_port(PORT_QCS_RELAY)
		if (LWS_IPV4)
			set(QCS_RELAY_ADS 127.0.0.1)
		else()
			set(QCS_RELAY_ADS ::1)
		endif()
		add_test(NAME ${SAMP}-reorder COMMAND ${SAMP}
				--server ${QCS_RELAY_ADS} -p ${PORT_QCS_REORDER}
				--relay ${PORT_QCS_RELAY} --write-size 100)
		set_tests_properties(${SAMP}-reorder PROPERTIES
					     WORKING_DIRECTORY .
					     TIMEOUT 60)

		#
		# The same with the CUBIC congestion controller on both sides,
		# otherwise never selected: the controller's in-flight accounting
		# over the relay's reordering and drops
		#
		lws_get_free_port(PORT_QCS_CUBIC)
		lws_get_free_port(PORT_QCS_CUBIC_RELAY)
		add_test(NAME ${SAMP}-cubic COMMAND ${SAMP}
				--server ${QCS_RELAY_ADS} -p ${PORT_QCS_CUBIC}
				--relay ${PORT_QCS_CUBIC_RELAY} --write-size 100
				--cubic)
		set_tests_properties(${SAMP}-cubic PROPERTIES
					     WORKING_DIRECTORY .
					     TIMEOUT 60)

		#
		# Through the relay with stray long header packets of another
		# connection sent to the client during and after the handshake:
		# the client must drop them without them changing its
		# connection (RFC 9000 7.2, RFC 9368)
		#
		lws_get_free_port(PORT_QCS_STRAY)
		lws_get_free_port(PORT_QCS_STRAY_RELAY)
		add_test(NAME ${SAMP}-stray COMMAND ${SAMP}
				--server ${QCS_RELAY_ADS} -p ${PORT_QCS_STRAY}
				--relay ${PORT_QCS_STRAY_RELAY} --stray)
		set_tests_properties(${SAMP}-stray PROPERTIES
					     WORKING_DIRECTORY .
					     TIMEOUT 60)

		#
		# The same with the server sending a Retry before it accepts the
		# client (RFC 9000 8.1.2): the client must see the connection
		# IDs of the Retry exchange repeated in the server's transport
		# parameters (RFC 9000 7.3)
		#
		lws_get_free_port(PORT_QCS_RETRY)
		add_test(NAME ${SAMP}-retry COMMAND ${SAMP}
				--server ${LWS_CTEST_SERVER_RESOLVE} -p ${PORT_QCS_RETRY})
		set_tests_properties(${SAMP}-retry PROPERTIES
					     ENVIRONMENT "LWS_QUIC_FORCE_RETRY=1"
					     WORKING_DIRECTORY .
					     TIMEOUT 20)
	endif()
endif()
