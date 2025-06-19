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

	option(LWS_WITH_TLS_JIT_TRUST "With JIT Trust" ON)
	set(LWS_WITH_TLS_JIT_TRUST ON)

        option(LWS_WITH_COMPRESSED_BACKTRACES "Build with support for compressed backtraces" ON)
        set(LWS_WITH_COMPRESSED_BACKTRACES ON)
        set(LWS_COMPRESSED_BACKTRACES_SNIP_PRE 2 CACHE STRING "Amount of callstack to snip from top" FORCE)
        set(LWS_COMPRESSED_BACKTRACES_SNIP_POST 2 CACHE STRING "Amount of callstack to snip from bottom" FORCE)

        option(LWS_WITH_ALLOC_METADATA_LWS "Build lws_*alloc() with compressed backtraces (requires WITH_COMPRESSED_BACKTRACES)" OFF)
        set(LWS_WITH_ALLOC_METADATA_LWS OFF)

        option(LWS_WITH_OTA "Build with support for Over The Air update download and validation" ON)
        set(LWS_WITH_OTA ON)

        set(LWS_OTA_VARIANT "esp32-waveshare-104-212" CACHE STRING "Build variant for OTA filtering" FORCE)
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
