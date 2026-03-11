project(lws-minimal-raw-dht-zone-client C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-raw-dht-zone-client)
set(SRCS minimal-raw-dht-zone-client.c )

set(requirements 1)
require_lws_config(LWS_WITH_DHT 1 requirements)
message(STATUS "ZONE: LWS_WITH_DHT req=${requirements}")
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)
message(STATUS "ZONE: LWS_WITH_SYS_ASYNC_DNS req=${requirements}")
require_lws_config(LWS_WITH_JOSE 1 requirements)
message(STATUS "ZONE: LWS_WITH_JOSE req=${requirements}")

if (requirements)
	add_executable(${SAMP} ${SRCS})
	
	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	if (NOT LWS_WITH_PLUGINS_BUILTIN AND NOT LWS_WITH_PLUGINS)
		target_compile_definitions(${SAMP} PRIVATE LWS_BUILDING_SHARED)
		# Link against the plugin so it can instantiate lws-dht-dnssec
		add_dependencies(${SAMP} protocol_lws_dht_dnssec)
	endif()

	install(TARGETS ${SAMP}
		RUNTIME DESTINATION ${LWS_INSTALL_BIN_DIR}
		COMPONENT core)

endif()
