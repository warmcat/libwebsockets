project(lws-unit-tests-smtp-client)
cmake_minimum_required(VERSION 2.8)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-unit-tests-smtp-client)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SMTP 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared)
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets)
	endif()
endif()
