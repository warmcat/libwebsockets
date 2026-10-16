project(lws-api-test-plugins C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-plugins)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_PLUGINS 1 requirements)
require_lws_config(LWS_WITH_PLUGINS_BUILTIN 0 requirements)

#
# The plugins are only built as separate libs beside a shared lws
#

if (requirements AND websockets_shared)

	add_executable(${SAMP} ${SRCS})
	target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
	add_dependencies(${SAMP} websockets_shared)

	#
	# The plugins are shared libs like lws itself, so they're built in the
	# same dir
	#

	add_test(NAME api-test-plugins COMMAND ${SAMP}
		 --dir $<TARGET_FILE_DIR:websockets_shared>
		 --suffix ${CMAKE_SHARED_LIBRARY_SUFFIX})

	#
	# The first load of a new library can be slow, eg, seconds per plugin
	# on macOS, and every test's context loads all the plugins.  So ctest
	# also runs this before any test starts, to have that over with once,
	# instead of the tests starting together each waiting on it for longer
	# than their peers will wait for them to listen.  warm.cmake never
	# fails, since that would stop ctest running anything: the test above
	# says what's wrong.
	#
	# The test's exe is in a dir per config with a multi-config generator,
	# and CTestCustom.cmake can't tell which ctest is running, so there's
	# no warm-up with those.
	#

	get_property(_multi GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
	if (NOT _multi)
		set_property(GLOBAL APPEND PROPERTY LWS_CTEST_PRE_TEST
			"\"${CMAKE_COMMAND}\" \"-DEXE=$<TARGET_FILE:${SAMP}>\" \"-DDIR=$<TARGET_FILE_DIR:websockets_shared>\" \"-DSUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}\" -P \"${CMAKE_CURRENT_SOURCE_DIR}/warm.cmake\"")
	endif()
endif()
