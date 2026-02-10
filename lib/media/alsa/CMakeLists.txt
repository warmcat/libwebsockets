if (LWS_WITH_ALSA)
	set(SRCS alsa.c)
	add_library(alsa STATIC ${SRCS})
	target_include_directories(alsa PRIVATE
		../../../lib/core
		../../../include
		../../../lib/plat
		../../../lib/plat/unix
		../../../lib/tls
		../../../lib/secure-streams
		../../../lib/event-libs
		../../../lib/system/smd
		../../../lib/system/metrics
		../../../lib/core-net
		../../../lib/roles
		../../../lib/roles/http
		../../../lib/roles/h1
		../../../lib/roles/h2
		../../../lib/roles/ws
		../../../lib/roles/http/compression
		../../../lib/roles/cgi
		../../../lib/roles/raw-proxy
		)
	target_link_libraries(alsa websockets asound)
endif()
