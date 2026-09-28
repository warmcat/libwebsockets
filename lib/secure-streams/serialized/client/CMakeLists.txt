include_directories(../../../core
		    ../../../core-net
		    ../../../plat/unix
		    ../../../plat/freertos
		    ../../../tls
		    ../../../event-libs
		    ../../../sansio
		    ../../../io
		    ../../../sansio/http
		    ../../../sansio/h1
		    ../../../sansio/h2
		    ../../../sansio/ws
		    ../../../sansio/mqtt
		    ../../../sansio/raw

		    ../../../system
		    ../../../system/smd
		    ../../../system/fault-injection
		    ../../../system/metrics

		    ${LIBUV_INCLUDE_DIRS}
		    )


foreach(libpath ${LWS_LIB_BUILD_INC_PATHS})
		include_directories(${libpath})
endforeach()

