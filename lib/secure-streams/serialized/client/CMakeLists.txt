include_directories(../../../core
		    ../../../core-net
		    ../../../plat/unix
		    ../../../plat/freertos
		    ../../../tls
		    ../../../event-libs
		    ../../../roles
		    ../../../roles/http
		    ../../../roles/h1
		    ../../../roles/h2
		    ../../../roles/ws
		    ../../../roles/mqtt
		    ../../../roles/raw

		    ../../../system
		    ../../../system/smd
		    ../../../system/fault-injection
		    ../../../system/metrics

		    ${LIBUV_INCLUDE_DIRS}
		    )


foreach(libpath ${LWS_LIB_BUILD_INC_PATHS})
		include_directories(${libpath})
endforeach()

add_library(lws-sspc STATIC
		sspc.c
		sspc-transport.c
		sspc-deserialize.c
		../../../core/lws_dll2.c
		../../../core-net/lws-dsh.c
		)

	target_compile_definitions(lws-sspc PUBLIC STANDALONE)

