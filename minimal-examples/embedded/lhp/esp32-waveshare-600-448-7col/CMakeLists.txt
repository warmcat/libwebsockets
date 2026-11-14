cmake_minimum_required(VERSION 3.10)

if (ESP_PLATFORM)

	set(CMAKE_C_FLAGS "-DLWS_DISPLAY_TYPE=$ENV{LWS_DISPLAY_TYPE}" CACHE STRING x FORCE)
	#message(FATAL_ERROR "ldt $ENV{LWS_DISPLAY_TYPE}")

	include($ENV{IDF_PATH}/tools/cmake/project.cmake)
	project(lws-minimal-esp32 C)
	enable_testing()

	target_link_libraries(lws-minimal-esp32.elf PRIVATE websockets)

	option(LWS_WITH_DRIVERS "With generic drivers for gpio, i2c, display etc" ON)
	set(LWS_WITH_DRIVERS ON)
	option(LWS_WITH_SECURE_STREAMS "With secure streams" ON)
	set(LWS_WITH_SECURE_STREAMS ON)
	option(LWS_WITH_LWSAC "With lwsac" ON)
	set(LWS_WITH_LWSAC ON)
	option(LWS_WITH_STRUCT_JSON "With lws_struct JSON" ON)
	set(LWS_WITH_STRUCT_JSON ON)
	option(LWS_WITH_SYS_NTPCLIENT "With ntpclient" ON)
        set(LWS_WITH_SYS_NTPCLIENT ON)
	# while an AP to be set up, every name is us, see lws_wifi_provision_create()
	option(LWS_WITH_SYS_CAPTIVE_DNS "With captive portal dns" ON)
	set(LWS_WITH_SYS_CAPTIVE_DNS ON)

	option(LWS_WITH_TLS_JIT_TRUST "With JIT Trust" ON)
	set(LWS_WITH_TLS_JIT_TRUST ON)

	#
	# Protocol mix for this variant: http/1.1 + h3, no h2.
	#
	# h1 is needed for the captive portal detection stream, which is
	# cleartext GET on port 80 and so can't be anything else.  Everything
	# that actually talks to libwebsockets.org (the carousel page fetches
	# and the OTA download) goes over h3 / QUIC instead of h2, so we can
	# see what the QUIC role costs us on the heap compared to h2.
	#
	# The SS policy in ../policy.h picks h3 for those streams by itself
	# when h2 isn't built (it prefers h2 when both are available, so the
	# other boards' builds are unaffected).
	#
	# NOTE h3 on an esp32 has two build-time requirements:
	#
	#  - the IDF mbedtls must be one with the lws QUIC transport ops
	#    patches, see https://libwebsockets.org/git/mbedtls/log?h=development
	#    and ../README.md for how to give esp-idf v6.1 one
	#    ... the lws build fails with a FATAL_ERROR explaining this if not
	#
	#  - CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y in sdkconfig, since QUIC only
	#    exists on TLS1.3 (this example's sdkconfig sets it)
	#
	option(LWS_ROLE_H1 "With http/1.1" ON)
	set(LWS_ROLE_H1 ON)
	option(LWS_WITH_HTTP2 "With http/2" OFF)
	set(LWS_WITH_HTTP2 OFF)
	option(LWS_WITH_HTTP3 "With http/3" ON)
	set(LWS_WITH_HTTP3 ON)
	option(LWS_WITH_UDP "With UDP (needed by QUIC)" ON)
	set(LWS_WITH_UDP ON)

	option(LWS_WITH_COMPRESSED_BACKTRACES "Build with support for compressed backtraces" ON)
	set(LWS_WITH_COMPRESSED_BACKTRACES ON)
	set(LWS_COMPRESSED_BACKTRACES_SNIP_PRE 2 CACHE STRING "Amount of callstack to snip from top" FORCE)
	set(LWS_COMPRESSED_BACKTRACES_SNIP_POST 2 CACHE STRING "Amount of callstack to snip from bottom" FORCE)

	option(LWS_WITH_ALLOC_METADATA_LWS "Build lws_*alloc() with compressed backtraces (requires WITH_COMPRESSED_BACKTRACES)" OFF)
	set(LWS_WITH_ALLOC_METADATA_LWS OFF)

	option(LWS_WITH_OTA "Build with support for Over The Air update download and validation" ON)
	set(LWS_WITH_OTA ON)

	set(LWS_OTA_VARIANT "esp32-waveshare-600-448-7col" CACHE STRING "Build variant for OTA filtering" FORCE)
	set(LWS_OTA_PUBLIC_JWK_FILE "$ENV{HOME}/.lws_ota/libwebsockets.org-ota-v1.public.jwk" CACHE STRING "JWK path" FORCE)

	set(CMAKE_BUILD_TYPE RELEASE)

	add_subdirectory(libwebsockets)

	add_test(NAME flashing COMMAND idf.py flash)
	set_tests_properties(flashing PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
			     TIMEOUT 120)

	add_test(NAME boot COMMAND /usr/local/bin/sai-expect)
	set_tests_properties(boot PROPERTIES
			     DEPENDS flashing
			     TIMEOUT 60)

endif()
