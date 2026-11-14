idf_component_register(SRCS
		../../main.c
		../../boot-ui.c
		../../settings-ui.c
		../../update-ui.c
		../../lhp-ss.c
		devices.c
		INCLUDE_DIRS "../libwebsockets/include;${IDF_PATH}/components/spi_flash/include;${IDF_PATH}/components/nvs_flash/include")

	target_link_libraries(${COMPONENT_LIB} PRIVATE websockets)

# the boot overlay's icons, from contrib/assets/boot-status
include(${CMAKE_CURRENT_LIST_DIR}/../../boot-icons.cmake)
lhp_boot_icons(${CMAKE_CURRENT_BINARY_DIR}/boot-icons.h
	       ${CMAKE_CURRENT_LIST_DIR}/../libwebsockets)

# the product's own, at the top of the settings, see ../../product.cmake
include(${CMAKE_CURRENT_LIST_DIR}/../../product.cmake)
lhp_product(${CMAKE_CURRENT_BINARY_DIR}/product.h
	    "ESP-WROVER-KIT"
	    ${CMAKE_CURRENT_LIST_DIR}/..)
target_include_directories(${COMPONENT_LIB} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
include_directories(../build/libwebsockets)
