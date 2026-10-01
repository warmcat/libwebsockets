set(SUB "sai-web")

set(CPACK_DEBIAN_SERVER_PACKAGE_NAME ${SUB})

set(SRCS
	w-sai.c
	w-comms.c
	w-artifact.c
	w-rss.c
	w-ws-server.c
	w-ws-browser.c
	w-findings.c
	../common/c-utils.c
	../common/c-pool.c
	../common/c-conf.c
	../common/c-sqlite3.c
	../common/struct-metadata.c
)

set(requirements 1)
require_lws_config(LWS_WITH_STRUCT_SQLITE3	1 requirements)
require_lws_config(LWS_WITH_SERVER		1 requirements)
require_lws_config(LWS_WITH_GENCRYPTO		1 requirements)
require_lws_config(LWS_WITH_UNIX_SOCK		1 requirements)

if (requirements)
	add_executable(${SUB} ${SRCS})
add_dependencies(${SUB} sai_git_hash)
	if (APPLE)
		set_property(TARGET sai-web PROPERTY MACOSX_RPATH YES)
	endif()
	#	set(CMAKE_C_FLAGS "-ffunction-sections -Wl,--gc-sections -Wl,--print-gc-sections ${CMAKE_C_FLAGS}" )

	#
	# sqlite3 paths (web)
	#
	find_path(   SQLITE3_INC_PATH NAMES "sqlite3.h")
	find_library(SQLITE3_LIB_PATH NAMES "sqlite3")
	
	if (SQLITE3_INC_PATH AND SQLITE3_LIB_PATH)
		include_directories(BEFORE "${SQLITE3_INC_PATH}")
	else()
		message(FATAL_ERROR " Unable to find sqlite3")
	endif()

	target_link_libraries(${SUB} ${SQLITE3_LIB_PATH})

       	include_directories(BEFORE "${SAI_LWS_INC_PATH}")

	CHECK_C_SOURCE_COMPILES("#include <libwebsockets.h>\nint
	main(void) {\n#if defined(LWS_HAVE_LIBCAP)\n return
		0;\n#else\n fail;\n#endif\n return 0;\n}\n" HAS_LIBCAP)
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

	if (MSVC)
		target_link_libraries(${SUB} ws2_32.lib userenv.lib psapi.lib iphlpapi.lib)
	endif()
	
	install(TARGETS ${SUB}
		RUNTIME DESTINATION "${BIN_DIR}" COMPONENT web)
	install(
		FILES ../../assets/index.html
		      ../../assets/OpenSans-Light.ttf
		      ../../assets/rebuild.png
		      ../../assets/delete.png
		      ../../assets/rss.png
		      ../../assets/passed.svg
		      ../../assets/failed.svg
		      ../../assets/locked.svg
		      ../../assets/coverity.svg
		      ../../assets/sai.css
		      ../../assets/sai.js
		      ../../assets/terminal-core.js
		      ../../assets/sai-terminal.js
		      ../../assets/sai.svg
		      ../../assets/sai-icon.svg
		      ../../assets/builder-instance.svg
		      ../../assets/builder-instance.png
		      ../../assets/builder.png
		      ../../assets/favicon.ico
		      ../../assets/strict-csp.svg
		      ../../assets/lws-common.js
		      ../../assets/gs/lwsgs.js
		      ../../assets/gs/lwsgs.css
		      	../../assets/arch-aarch64-a72a55-rk3588.svg
			../../assets/arch-aarch64-a72-bcm2711-rpi4.svg
			../../assets/arch-aarch64.svg
			../../assets/arch-arm32-m4-mt7697-usi.svg
			../../assets/arch-arm32.svg
			../../assets/arch-freertos.svg
			../../assets/arch-riscv64-virt.svg
			../../assets/arch-riscv.svg
			../../assets/arch-riscv64.svg
			../../assets/arch-risc-v.svg
			../../assets/arch-x86_64-amd.svg
			../../assets/arch-x86_64.svg
			../../assets/x86_64.svg
			../../assets/arch-x86_64-intel-i3.svg
			../../assets/arch-x86_64-intel.svg
			../../assets/arch-xl6-esp32.svg
			../../assets/artifact.svg
			../../assets/builder.svg
			../../assets/decal-2.svg
			../../assets/decal-3.svg
			../../assets/decal-4.svg
			../../assets/decal-5.svg
			../../assets/decal-6.svg
			../../assets/freertos-espidf.svg
			../../assets/freertos-linkit.svg
			../../assets/git.svg
			../../assets/jsplease.svg
			../../assets/linux-android.svg
			../../assets/linux-centos-8.svg
			../../assets/linux-fedora-32-riscv.svg
			../../assets/linux-fedora-32.svg
			../../assets/linux-fedora44.svg
			../../assets/linux-debian13.svg
			../../assets/linux-gentoo.svg
			../../assets/linux-ubuntu-1804.svg
			../../assets/linux-ubuntu-2004.svg
			../../assets/linux-ubuntu-xenial.svg
			../../assets/netbsd-iOS.svg
			../../assets/netbsd-OSX-catalina.svg
			../../assets/netbsd-OSX-bigsur.svg
			../../assets/rocky9.svg
			../../assets/rocky9-ca.svg
			../../assets/sai-event.svg
			../../assets/sai-icon.svg
			../../assets/sai.svg
			../../assets/stop.svg
			../../assets/strict-csp.svg
			../../assets/tc-clang.svg
			../../assets/tc-gcc.svg
			../../assets/tc-llvm.svg
			../../assets/tc-mingw32.svg
			../../assets/tc-mingw64.svg
			../../assets/tc-msvc.svg
			../../assets/tc-msvc-schannel.svg
			../../assets/tc-wmbedtlsmsvc.svg
			../../assets/tc-noptmsvc.svg
			../../assets/ubuntu.svg
			../../assets/ubuntu-noble.svg
			../../assets/ubuntu-focal-aarch64.svg
			../../assets/virt-qemu.svg
			../../assets/w10.svg
			../../assets/w11.svg
			../../assets/freebsd.svg

		DESTINATION "${DATA_DIR}/sai/assets"
		COMPONENT web)

endif(requirements)
