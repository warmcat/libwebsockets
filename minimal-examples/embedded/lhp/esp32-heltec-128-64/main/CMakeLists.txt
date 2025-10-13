idf_component_register(SRCS
		../../main.c
		../../lhp-ss.c
		devices.c
		INCLUDE_DIRS "../libwebsockets/include;${IDF_PATH}/components/spi_flash/include;${IDF_PATH}/components/nvs_flash/include")

	target_link_libraries(${COMPONENT_LIB} PRIVATE websockets)
include_directories(../build/libwebsockets)
