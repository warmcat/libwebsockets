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

