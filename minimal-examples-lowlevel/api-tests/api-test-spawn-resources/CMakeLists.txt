project(lws-api-test-spawn-resources C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-spawn-resources)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SPAWN 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# the helpers it spawns are itself, run with --hog and --tree
	add_test(NAME api-test-spawn-resources COMMAND lws-api-test-spawn-resources)
	set_tests_properties(api-test-spawn-resources
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-spawn-resources
			     TIMEOUT 120)

	#
	# And again on each event lib in the build.  Not all of them report
	# the far end of the helper's stdin going away while we're not writing
	# on it, so lws must not depend on that to know the helper has gone.
	#
	# The event lib plugins are found on LD_LIBRARY_PATH; the one ctest is
	# run with may be relative to somewhere else than our working dir, so
	# point it at the build tree's plugins ourselves.
	#
	foreach(evl uv:LIBUV event:LIBEVENT ev:LIBEV glib:GLIB sd:SDEVENT
		    uloop:ULOOP)
		string(REPLACE ":" ";" evl ${evl})
		list(GET evl 0 evl_name)
		list(GET evl 1 evl_opt)

		if (LWS_WITH_${evl_opt})
			add_test(NAME api-test-spawn-resources-${evl_name}
				 COMMAND lws-api-test-spawn-resources)
			set_tests_properties(api-test-spawn-resources-${evl_name}
				PROPERTIES
				WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-spawn-resources
				ENVIRONMENT "LWS_EVLIB=${evl_name};LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
				TIMEOUT 120)
		endif()
	endforeach()
endif()
