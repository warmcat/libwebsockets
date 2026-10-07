set(SUB "sai-builder")
set(CPACK_DEBIAN_BUILDER_PACKAGE_NAME "sai-builder")

set(SRCS
	b-sai.c
	b-win32-service.c
	b-conf.c
	b-ws-server.c
	b-nspawn.c
	b-task.c
	b-artifacts.c
	b-pool.c
	b-env.c
	b-logproxy.c
	b-refproxy.c
	b-load.c
	b-metrics.c
	b-suspender.c
	b-deletion.c
	b-power.c
	b-whoami.c
	../common/c-utils.c
	../common/c-pool.c
	../common/struct-metadata.c
)

set(requirements 1)
require_lws_config(LWS_WITH_CLIENT		1 requirements)
require_lws_config(LWS_WITH_SPAWN		1 requirements)
require_lws_config(LWS_WITH_STRUCT_JSON		1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS	1 requirements)
require_lws_config(LWS_WITH_DIR			1 requirements)

if (requirements)
	add_executable(${SUB} ${SRCS})
add_dependencies(${SUB} sai_git_hash)
	if (APPLE)
		set_property(TARGET ${SUB} PROPERTY MACOSX_RPATH YES)
               set(CMAKE_MACOSX_RPATH 1)
               set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

               add_custom_command(TARGET ${SUB}
                       POST_BUILD COMMAND 
                       ${CMAKE_INSTALL_NAME_TOOL} -add_rpath "/usr/local/lib"
                       $<TARGET_FILE:${SUB}>)

               set(CMAKE_C_FLAGS "-I/usr/local/include ${CMAKE_C_FLAGS}")
               link_directories("/usr/local/lib")
	endif()


	#configure_file("${PROJECT_SOURCE_DIR}/cmake/sai_config_private.h.in"
	#	       "${PROJECT_BINARY_DIR}/sai_config_private.h")
	#
	#target_include_directories(${SUB} PRIVATE "${PROJECT_BINARY_DIR}")



	if (SAI_LWS_INC_PATH)
		target_include_directories(${SUB} PRIVATE ${SAI_LWS_INC_PATH})
	endif()

	if (HAS_LIBCAP)
		find_library(CAP_LIB_PATH NAMES "cap")
	endif()

	target_link_libraries(${SUB} websockets ${SAI_LWS_LIB_PATH} ${LIBWEBSOCKETS_DEP_LIBS})
	
	message("LWS_OPENSSL_LIBRARIES ${SUB} '${LWS_OPENSSL_LIBRARIES}'")
	if (LWS_OPENSSL_LIBRARIES)
		target_link_libraries(${SUB} ${LWS_OPENSSL_LIBRARIES})
	endif()
	
	if (SAI_EXT_PTHREAD_LIBRARIES)
		target_link_libraries(${SUB} ${SAI_EXT_PTHREAD_LIBRARIES})
	endif()
	if (HAS_LIBCAP)
		target_link_libraries(${SUB} ${CAP_LIB_PATH})
	endif()

	if (MSVC OR WIN32)
		target_link_libraries(${SUB} ws2_32.lib userenv.lib psapi.lib iphlpapi.lib advapi32.lib dbghelp.lib)
	endif()

	if (MSVC OR WIN32)
		# Auto-copy dependencies (DLLs) during install
		install(CODE "
			include(BundleUtilities)
			fixup_bundle(\"\${CMAKE_INSTALL_PREFIX}/${BIN_DIR}/sai-builder.exe\" \"\" \"\")
			" COMPONENT builder)
	endif()

	install(TARGETS "sai-builder"
		RUNTIME DESTINATION "${BIN_DIR}" COMPONENT builder)


endif(requirements)
include(CPack)
