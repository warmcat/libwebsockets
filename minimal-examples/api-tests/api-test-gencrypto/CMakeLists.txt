project(lws-api-test-gencrypto)
cmake_minimum_required(VERSION 2.8)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-gencrypto)
set(SRCS main.c lws-genaes.c lws-genec.c)

set(requirements 1)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)


if (requirements)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-gencrypto COMMAND lws-api-test-gencrypto)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared)
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets)
	endif()
endif()

