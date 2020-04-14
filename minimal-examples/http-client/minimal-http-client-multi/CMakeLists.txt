project(lws-minimal-http-client-multi)
cmake_minimum_required(VERSION 2.8)
include(CheckCSourceCompiles)

set(SAMP lws-minimal-http-client-multi)
set(SRCS minimal-http-client-multi.c)

# If we are being built as part of lws, confirm current build config supports
# reqconfig, else skip building ourselves.
#
# If we are being built externally, confirm installed lws was configured to
# support reqconfig, else error out with a helpful message about the problem.
#
MACRO(require_lws_config reqconfig _val result)

	if (DEFINED ${reqconfig})
	if (${reqconfig})
		set (rq 1)
	else()
		set (rq 0)
	endif()
	else()
		set(rq 0)
	endif()

	if (${_val} EQUAL ${rq})
		set(SAME 1)
	else()
		set(SAME 0)
	endif()

	if (LWS_WITH_MINIMAL_EXAMPLES AND NOT ${SAME})
		if (${_val})
			message("${SAMP}: skipping as lws being built without ${reqconfig}")
		else()
			message("${SAMP}: skipping as lws built with ${reqconfig}")
		endif()
		set(${result} 0)
	else()
		if (LWS_WITH_MINIMAL_EXAMPLES)
			set(MET ${SAME})
		else()
			CHECK_C_SOURCE_COMPILES("#include <libwebsockets.h>\nint main(void) {\n#if defined(${reqconfig})\n return 0;\n#else\n fail;\n#endif\n return 0;\n}\n" HAS_${reqconfig})
			if (NOT DEFINED HAS_${reqconfig} OR NOT HAS_${reqconfig})
				set(HAS_${reqconfig} 0)
			else()
				set(HAS_${reqconfig} 1)
			endif()
			if ((HAS_${reqconfig} AND ${_val}) OR (NOT HAS_${reqconfig} AND NOT ${_val}))
				set(MET 1)
			else()
				set(MET 0)
			endif()
		endif()
		if (NOT MET)
			if (${_val})
				message(FATAL_ERROR "This project requires lws must have been configured with ${reqconfig}")
			else()
				message(FATAL_ERROR "Lws configuration of ${reqconfig} is incompatible with this project")
			endif()
		endif()
	
	endif()
ENDMACRO()


set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	
       #
       # instantiate the server per sai builder instance, they are running in the same
       # machine context in parallel so they can tread on each other otherwise
       #
       set(LOCALTESTPORT "7670")
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "0")
               set(LOCALTESTPORT 7671)
       endif()
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "1")
               set(LOCALTESTPORT 7672)
       endif()
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "2")
               set(LOCALTESTPORT 7673)
       endif()
       if ("$ENV{SAI_INSTANCE_IDX}" STREQUAL "3")
               set(LOCALTESTPORT 7674)
       endif()


# hack
if (NOT WIN32 AND LWS_WITH_SERVER)

	#
	# Tests against built server running locally (needs daemonization...)
	#

if (WIN32)
	add_test(NAME slocalserver COMMAND cmd.exe /c start /b $<TARGET_FILE:lws-minimal-http-server-tls> --port ${LOCALTESTPORT})
	add_test(NAME clocalserver COMMAND taskkill /F /IM $<TARGET_FILE_NAME:lws-minimal-http-server-tls> /T)
	add_test(NAME slocalserver-post COMMAND cmd.exe /c start /b $<TARGET_FILE:test-server> -s --port 1${LOCALTESTPORT})
	add_test(NAME clocalserver-post COMMAND taskkill /F /IM $<TARGET_FILE_NAME:test-server> /T)
else()
	add_test(NAME slocalserver COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh $<TARGET_FILE:lws-minimal-http-server-tls> --port ${LOCALTESTPORT})
	add_test(NAME clocalserver COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh $<TARGET_FILE_NAME:lws-minimal-http-server-tls>)
	add_test(NAME slocalserver-post COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh $<TARGET_FILE:test-server> -s --port 1${LOCALTESTPORT})
	add_test(NAME clocalserver-post COMMAND ${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh $<TARGET_FILE_NAME:test-server>)
endif()

	set_tests_properties(slocalserver PROPERTIES
       		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-server/minimal-http-server-tls
		FIXTURES_SETUP localserver
		TIMEOUT 800)
	set_tests_properties(clocalserver PROPERTIES
		FIXTURES_CLEANUP localserver)

	set_tests_properties(slocalserver-post PROPERTIES
       		WORKING_DIRECTORY .
		FIXTURES_SETUP localserver-post
		TIMEOUT 800)
	set_tests_properties(clocalserver-post PROPERTIES
		FIXTURES_CLEANUP localserver-post)

	#
	# Tests against local server peer
	#

	add_test(NAME http-client-multi COMMAND lws-minimal-http-client-multi -l --port ${LOCALTESTPORT})
	add_test(NAME http-client-multi-h1 COMMAND lws-minimal-http-client-multi --h1 -l --port ${LOCALTESTPORT})
	add_test(NAME http-client-multi-pipe COMMAND lws-minimal-http-client-multi -p -l --port ${LOCALTESTPORT})
	add_test(NAME http-client-multi-h1-pipe COMMAND lws-minimal-http-client-multi --h1 -p -l --port ${LOCALTESTPORT})
	add_test(NAME http-client-multi-stag COMMAND lws-minimal-http-client-multi -s -l --port ${LOCALTESTPORT})
	add_test(NAME http-client-multi-stag-h1 COMMAND lws-minimal-http-client-multi --h1 -s -l --port ${LOCALTESTPORT})
	add_test(NAME http-client-multi-stag-pipe COMMAND lws-minimal-http-client-multi -p -s -l --port ${LOCALTESTPORT})
	add_test(NAME http-client-multi-stag-h1-pipe COMMAND lws-minimal-http-client-multi --h1 -p -s -l --port ${LOCALTESTPORT})
	set_tests_properties(http-client-multi
			     http-client-multi-h1
			     http-client-multi-pipe
			     http-client-multi-h1-pipe
			     http-client-multi-stag
			     http-client-multi-stag-h1
			     http-client-multi-stag-pipe
			     http-client-multi-stag-h1-pipe
			     PROPERTIES
			     FIXTURES_REQUIRED "localserver;localserver-post"
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
			     TIMEOUT 20)

	# POSTs against local http-server-form-post
	add_test(NAME http-client-multi-post COMMAND lws-minimal-http-client-multi --post -l --port 1${LOCALTESTPORT})
	add_test(NAME http-client-multi-post-h1 COMMAND lws-minimal-http-client-multi --post --h1 -l --port 1${LOCALTESTPORT})
	add_test(NAME http-client-multi-post-pipe COMMAND lws-minimal-http-client-multi --post -p -l --port 1${LOCALTESTPORT})
	add_test(NAME http-client-multi-post-h1-pipe COMMAND lws-minimal-http-client-multi --post --h1 -p -l --port 1${LOCALTESTPORT})
	add_test(NAME http-client-multi-post-stag COMMAND lws-minimal-http-client-multi --post -s -l -d1151 --port 1${LOCALTESTPORT})
	add_test(NAME http-client-multi-post-stag-h1 COMMAND lws-minimal-http-client-multi --post --h1 -d1151 -s -l --port 1${LOCALTESTPORT})
	add_test(NAME http-client-multi-post-stag-pipe COMMAND lws-minimal-http-client-multi --post -p -s -l --port 1${LOCALTESTPORT})
	add_test(NAME http-client-multi-post-stag-h1-pipe COMMAND lws-minimal-http-client-multi --post --h1 -p -s -l --port 1${LOCALTESTPORT})
	set_tests_properties(http-client-multi-post
			     http-client-multi-post-h1
			     http-client-multi-post-pipe
			     http-client-multi-post-h1-pipe
			     http-client-multi-post-stag
			     http-client-multi-post-stag-h1
			     http-client-multi-post-stag-pipe
			     http-client-multi-post-stag-h1-pipe
			     PROPERTIES
			     FIXTURES_REQUIRED "localserver;localserver-post"
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
			     TIMEOUT 20)

	# confirm that the pipelined mode really is doing it in one connection
	add_test(NAME http-client-multi-restrict-pipe COMMAND lws-minimal-http-client-multi -d1151 --limit 1 -p -l --port ${LOCALTESTPORT})
	add_test(NAME http-client-multi-restrict-h1-pipe COMMAND lws-minimal-http-client-multi -d1151 --limit 1 --h1 -p -l --port ${LOCALTESTPORT})
	add_test(NAME http-client-multi-restrict-stag-pipe COMMAND lws-minimal-http-client-multi -d1151 --limit 1 -p -s -l --port ${LOCALTESTPORT})
	add_test(NAME http-client-multi-restrict-stag-h1-pipe COMMAND lws-minimal-http-client-multi -d1151 --limit 1 --h1 -p -s -l --port ${LOCALTESTPORT})
	set_tests_properties(http-client-multi-restrict-pipe
			     http-client-multi-restrict-h1-pipe
			     http-client-multi-restrict-stag-pipe
			     http-client-multi-restrict-stag-h1-pipe
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
			     FIXTURES_REQUIRED "localserver;localserver-post"
			     TIMEOUT 20)

	# confirm that we do fail with a one connection limit and no pipelining
	add_test(NAME http-client-multi-restrict-nopipe-fail COMMAND lws-minimal-http-client-multi --limit 1 -l --port ${LOCALTESTPORT})
	set_property(TEST http-client-multi-restrict-nopipe-fail PROPERTY WILL_FAIL TRUE)
	add_test(NAME http-client-multi-restrict-h1-nopipe-fail COMMAND lws-minimal-http-client-multi --limit 1 --h1 -l --port ${LOCALTESTPORT})
	set_property(TEST http-client-multi-restrict-h1-nopipe-fail PROPERTY WILL_FAIL TRUE)
	set_tests_properties(http-client-multi-restrict-nopipe-fail
			     http-client-multi-restrict-h1-nopipe-fail
			     PROPERTIES
			     FIXTURES_REQUIRED "localserver;localserver-post"
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
			     TIMEOUT 20)
endif(NOT WIN32 AND LWS_WITH_SERVER)

	if (LWS_CTEST_INTERNET_AVAILABLE)

		#
		# Tests against warmcat.com
		#

		# GETs
		add_test(NAME http-client-multi-warmcat COMMAND lws-minimal-http-client-multi -d1151)
		add_test(NAME http-client-multi-warmcat-h1 COMMAND lws-minimal-http-client-multi -d1151 --h1)
		add_test(NAME http-client-multi-warmcat-pipe COMMAND lws-minimal-http-client-multi -d1151 -p)
		add_test(NAME http-client-multi-warmcat-h1-pipe COMMAND lws-minimal-http-client-multi -d1151 --h1 -p)
		add_test(NAME http-client-multi-warmcat-stag COMMAND lws-minimal-http-client-multi -d1151 -s)
		add_test(NAME http-client-multi-warmcat-stag-h1 COMMAND lws-minimal-http-client-multi -d1151 --h1 -s)
		add_test(NAME http-client-multi-warmcat-stag-pipe COMMAND lws-minimal-http-client-multi -d1151 -p -s)
		add_test(NAME http-client-multi-warmcat-stag-h1-pipe COMMAND lws-minimal-http-client-multi -d1151 --h1 -p -s)
		set_tests_properties(http-client-multi-warmcat
				     http-client-multi-warmcat-h1
				     http-client-multi-warmcat-pipe
				     http-client-multi-warmcat-h1-pipe
				     http-client-multi-warmcat-stag
				     http-client-multi-warmcat-stag-h1
				     http-client-multi-warmcat-stag-pipe
				     http-client-multi-warmcat-stag-h1-pipe
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
				     TIMEOUT 20)

		# POSTs
		add_test(NAME http-client-multi-warmcat-post COMMAND lws-minimal-http-client-multi --post)
		add_test(NAME http-client-multi-warmcat-post-h1 COMMAND lws-minimal-http-client-multi --post --h1)
		add_test(NAME http-client-multi-warmcat-post-pipe COMMAND lws-minimal-http-client-multi --post -p)
		add_test(NAME http-client-multi-warmcat-post-h1-pipe COMMAND lws-minimal-http-client-multi --post --h1 -p)
		add_test(NAME http-client-multi-warmcat-post-stag COMMAND lws-minimal-http-client-multi --post -s)
		add_test(NAME http-client-multi-warmcat-post-stag-h1 COMMAND lws-minimal-http-client-multi --post --h1 -s)
		add_test(NAME http-client-multi-warmcat-post-stag-pipe COMMAND lws-minimal-http-client-multi --post -p -s)
		add_test(NAME http-client-multi-warmcat-post-stag-h1-pipe COMMAND lws-minimal-http-client-multi --post --h1 -p -s)
		set_tests_properties(http-client-multi-warmcat-post
				     http-client-multi-warmcat-post-h1
				     http-client-multi-warmcat-post-pipe
				     http-client-multi-warmcat-post-h1-pipe
				     http-client-multi-warmcat-post-stag
				     http-client-multi-warmcat-post-stag-h1
				     http-client-multi-warmcat-post-stag-pipe
				     http-client-multi-warmcat-post-stag-h1-pipe
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
				     TIMEOUT 20)

		# confirm that the pipelined mode really is doing it in one connection
		add_test(NAME http-client-multi-warmcat-restrict-pipe COMMAND lws-minimal-http-client-multi --ignore-sigterm --limit 1 -p)
		add_test(NAME http-client-multi-warmcat-restrict-h1-pipe COMMAND lws-minimal-http-client-multi --ignore-sigterm --limit 1 --h1 -p)
		add_test(NAME http-client-multi-warmcat-restrict-stag-pipe COMMAND lws-minimal-http-client-multi --ignore-sigterm --limit 1 -p -s)
		add_test(NAME http-client-multi-warmcat-restrict-stag-h1-pipe COMMAND lws-minimal-http-client-multi --ignore-sigterm --limit 1 --h1 -p -s)
		set_tests_properties(http-client-multi-warmcat-restrict-pipe
				     http-client-multi-warmcat-restrict-h1-pipe
				     http-client-multi-warmcat-restrict-stag-pipe
				     http-client-multi-warmcat-restrict-stag-h1-pipe
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
				     TIMEOUT 20)

		# confirm that we do fail with a one connection limit and no pipelining
		add_test(NAME http-client-multi-warmcat-restrict-nopipe-fail COMMAND lws-minimal-http-client-multi --ignore-sigterm --limit 1)
		add_test(NAME http-client-multi-warmcat-restrict-h1-nopipe-fail COMMAND lws-minimal-http-client-multi --ignore-sigterm --limit 1 --h1)
		set_tests_properties(http-client-multi-warmcat-restrict-nopipe-fail
				     http-client-multi-warmcat-restrict-h1-nopipe-fail
				     PROPERTIES
				     TIMEOUT 20
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
				     WILL_FAIL TRUE)

	# these don't fail if your RTT to warmcat.com is low, since it can complete transactions inside the stagger interval
	#	add_test(NAME http-client-multi-warmcat-restrict-stag-nopipe-fail COMMAND lws-minimal-http-client-multi --limit 1 -s)
	#	add_test(NAME http-client-multi-warmcat-restrict-stag-h1-nopipe-fail COMMAND lws-minimal-http-client-multi --limit 1 --h1 -s)
	#	set_tests_properties(http-client-multi-warmcat-restrict-stag-nopipe-fail
	#			     http-client-multi-warmcat-restrict-stag-h1-nopipe-fail
	#			     PROPERTIES
	#			     TIMEOUT 20
	#			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client-multi
	#			     WILL_FAIL TRUE)
	endif()


	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared)
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets)
	endif()
endif()
