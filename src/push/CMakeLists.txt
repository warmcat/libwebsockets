set(SUB "sai-push")
set(CPACK_DEBIAN_PUSH_PACKAGE_NAME "sai-push")

set(SRCS
	pu-sai.c
	pu-feed.c
	pu-git.c
	pu-state.c
	../common/c-utils.c
	../common/struct-metadata.c
)

set(requirements 1)
require_lws_config(LWS_WITH_CLIENT		1 requirements)
require_lws_config(LWS_WITH_STRUCT_JSON		1 requirements)
require_lws_config(LWS_WITH_SPAWN		1 requirements)

if (requirements)
	add_executable(${SUB} ${SRCS})
	add_dependencies(${SUB} sai_git_hash)
	if (APPLE)
		set_property(TARGET ${SUB} PROPERTY MACOSX_RPATH YES)
	endif()

	if (SAI_LWS_INC_PATH)
		target_include_directories(${SUB} PRIVATE ${SAI_LWS_INC_PATH})
	endif()

	target_link_libraries(${SUB} websockets ${SAI_LWS_LIB_PATH} ${LIBWEBSOCKETS_DEP_LIBS})

	if (LWS_OPENSSL_LIBRARIES)
		target_link_libraries(${SUB} ${LWS_OPENSSL_LIBRARIES})
	endif()

	if (SAI_EXT_PTHREAD_LIBRARIES)
		target_link_libraries(${SUB} ${SAI_EXT_PTHREAD_LIBRARIES})
	endif()

	install(TARGETS ${SUB}
		RUNTIME DESTINATION "${BIN_DIR}" COMPONENT push)
endif(requirements)
