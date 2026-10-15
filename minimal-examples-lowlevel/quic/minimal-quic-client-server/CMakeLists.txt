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
		# The client spreads its writes over 8s, longer than the server
		# reaps a connection that has been idle since its handshake:
		# the server must keep the connection, and the stream, while
		# the client is still sending on it
		#
		lws_get_free_port(PORT_QCS_SPREAD)
		add_test(NAME ${SAMP}-spread COMMAND ${SAMP}
				--server ${LWS_CTEST_SERVER_RESOLVE}
				-p ${PORT_QCS_SPREAD} --spread 8000)
		set_tests_properties(${SAMP}-spread PROPERTIES
					     WORKING_DIRECTORY .
					     TIMEOUT 60)

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
		# Through the relay losing all but the client's Initial packets
		# for 2s after its first Initial: the server, with an RTT sample
		# but left waiting for the client's Finished, must keep the
		# half-open connection within its handshake deadline, so the
		# handshake completes when the client's retransmissions get
		# through again
		#
		lws_get_free_port(PORT_QCS_OUTAGE)
		lws_get_free_port(PORT_QCS_OUTAGE_RELAY)
		add_test(NAME ${SAMP}-outage COMMAND ${SAMP}
				--server ${QCS_RELAY_ADS} -p ${PORT_QCS_OUTAGE}
				--relay ${PORT_QCS_OUTAGE_RELAY} --outage 2000)
		set_tests_properties(${SAMP}-outage PROPERTIES
					     WORKING_DIRECTORY .
					     TIMEOUT 60)

		#
		# Through the relay sending the client's first 1-RTT packet to
		# the server ahead of its Finished, and then losing its other
		# 1-RTT packets for 1s: the server must hold the early one until
		# its handshake completes and then process it, not lose it
		#
		lws_get_free_port(PORT_QCS_EARLY)
		lws_get_free_port(PORT_QCS_EARLY_RELAY)
		add_test(NAME ${SAMP}-early-1rtt COMMAND ${SAMP}
				--server ${QCS_RELAY_ADS} -p ${PORT_QCS_EARLY}
				--relay ${PORT_QCS_EARLY_RELAY} --early-1rtt)
		set_tests_properties(${SAMP}-early-1rtt PROPERTIES
					     WORKING_DIRECTORY .
					     TIMEOUT 60)

		#
		# Through the relay also sending the server copies of the
		# client's small packets, ahead of the originals, from an
		# address that never answers: the server must stay on its
		# validated path, probe the other address no faster than RFC
		# 9000 allows, and back off probing it after failing.  The
		# client's writes are spread over 12s, so the copies go on for
		# long enough to see the server fail and wait several times.
		#
		lws_get_free_port(PORT_QCS_FWD)
		lws_get_free_port(PORT_QCS_FWD_RELAY)
		add_test(NAME ${SAMP}-forwarder COMMAND ${SAMP}
				--server ${QCS_RELAY_ADS} -p ${PORT_QCS_FWD}
				--relay ${PORT_QCS_FWD_RELAY} --forwarder
				--write-size 64 --spread 12000)
		set_tests_properties(${SAMP}-forwarder PROPERTIES
					     WORKING_DIRECTORY .
					     TIMEOUT 60)

		#
		# Through the relay passing datagrams on as they come, as a path
		# with an MTU of 1500: each side must probe its way up to the
		# biggest datagrams lws sends, in probes of their own, and lose
		# none.  Then losing those bigger than 1400: each side must
		# settle on the biggest size that fits, after losing no more
		# than three probes of the next one up.
		#
		lws_get_free_port(PORT_QCS_PMTU)
		lws_get_free_port(PORT_QCS_PMTU_RELAY)
		add_test(NAME ${SAMP}-pmtu COMMAND ${SAMP}
				--server ${QCS_RELAY_ADS} -p ${PORT_QCS_PMTU}
				--relay ${PORT_QCS_PMTU_RELAY} --pmtu 1500)
		set_tests_properties(${SAMP}-pmtu PROPERTIES
					     WORKING_DIRECTORY .
					     TIMEOUT 60)

		lws_get_free_port(PORT_QCS_PMTU_SMALL)
		lws_get_free_port(PORT_QCS_PMTU_SMALL_RELAY)
		add_test(NAME ${SAMP}-pmtu-small COMMAND ${SAMP}
				--server ${QCS_RELAY_ADS} -p ${PORT_QCS_PMTU_SMALL}
				--relay ${PORT_QCS_PMTU_SMALL_RELAY} --pmtu 1400)
		set_tests_properties(${SAMP}-pmtu-small PROPERTIES
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
