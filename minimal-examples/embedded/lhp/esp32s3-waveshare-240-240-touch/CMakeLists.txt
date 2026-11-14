cmake_minimum_required(VERSION 3.10)

if (ESP_PLATFORM)

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
	option(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY "Static policy" OFF)
	set(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY OFF)
	option(LWS_WITH_TLS_JIT_TRUST "With JIT Trust" ON)
	set(LWS_WITH_TLS_JIT_TRUST ON)

	#
	# h1, h2 and h3.  The SS policy in ../policy.h prefers h2, and a
	# server that says by Alt-Svc it has h3 is raced over QUIC as well.
	#
	# h3 on an esp32 needs the IDF mbedtls to have the lws QUIC transport
	# ops patches (see ../README.md, the lws build stops with a FATAL_ERROR
	# saying so if not), and CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y, which this
	# example's sdkconfig sets, since QUIC only exists on TLS1.3
	#
	option(LWS_WITH_HTTP2 "With http/2" ON)
	set(LWS_WITH_HTTP2 ON)
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

	#
	# OTA needs the public key the firmware manifests are signed with, to
	# validate what it downloads.  A build box without it (CI) still builds
	# the example, with OTA left out.
	#
	set(LWS_OTA_PUBLIC_JWK_FILE "$ENV{HOME}/.lws_ota/libwebsockets.org-ota-v1.public.jwk" CACHE STRING "JWK path" FORCE)
	if (EXISTS "${LWS_OTA_PUBLIC_JWK_FILE}")
		option(LWS_WITH_OTA "Build with support for Over The Air update download and validation" ON)
		set(LWS_WITH_OTA ON)
		set(LWS_OTA_VARIANT "esp32s3-waveshare-240-240-touch" CACHE STRING "Build variant for OTA filtering" FORCE)
	else()
		message(STATUS "No OTA public key at ${LWS_OTA_PUBLIC_JWK_FILE}: building without OTA")
		set(LWS_WITH_OTA OFF)
	endif()

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
