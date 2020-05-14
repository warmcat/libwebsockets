cmake_minimum_required(VERSION 3.5)

if (ESP_PLATFORM)
	include($ENV{IDF_PATH}/tools/cmake/project.cmake)
	project(lws-minimal-esp32)
	enable_testing()

	target_link_libraries(lws-minimal-esp32.elf websockets)
	add_subdirectory(libwebsockets)

	add_test(NAME flashing COMMAND idf.py flash)
	set_tests_properties(flashing PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
			     TIMEOUT 120)

	add_test(NAME boot COMMAND /usr/local/bin/sai-expect)
	set_tests_properties(boot PROPERTIES
			     DEPENDS flashing
			     TIMEOUT 20)

endif()
