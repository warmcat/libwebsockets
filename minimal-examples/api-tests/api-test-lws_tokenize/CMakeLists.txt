project(lws-api-test-lws_tokenize)
cmake_minimum_required(VERSION 2.8)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-lws_tokenize)
set(SRCS main.c)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-lws_tokenize COMMAND lws-api-test-lws_tokenize)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared)
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets)
	endif()
