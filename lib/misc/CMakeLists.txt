#
# libwebsockets - small server side websockets and web server implementation
#
# Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# The strategy is to only export to PARENT_SCOPE
#
#  - changes to LIB_LIST
#  - changes to SOURCES
#  - includes via include_directories
#
# and keep everything else private

include_directories(.)
if (NOT LWS_ONLY_SSPC)
list(APPEND SOURCES
	misc/base64-decode.c
	misc/prng.c
	misc/lws-ring.c)

if (LWS_WITH_NETWORK)
	list(APPEND SOURCES
		misc/cache-ttl/lws-cache-ttl.c
		misc/cache-ttl/heap.c
		)

	if (LWS_WITH_CACHE_NSCOOKIEJAR)
		list(APPEND SOURCES
			misc/cache-ttl/file.c)
	endif()

endif()

if (LWS_WITH_COMPRESSED_BACKTRACES)
	list(APPEND SOURCES
		misc/backtrace.c)
endif()

if (LWS_WITH_FTS)
	list(APPEND SOURCES
		misc/fts/trie.c
		misc/fts/trie-fd.c)
endif()

if (LWS_WITH_GZINFLATE)
	list(APPEND SOURCES
		misc/upng-gzip.c)
endif()

if (LWS_WITH_UPNG)
	list(APPEND SOURCES
		misc/upng.c)
endif()
if (LWS_WITH_JPEG)
	list(APPEND SOURCES
		misc/jpeg.c)
endif()


if (LWS_WITH_DLO)
	list(APPEND SOURCES
		misc/dlo/dlo.c
		misc/dlo/dlo-rect.c
		misc/dlo/dlo-font-mcufont.c
		misc/dlo/dlo-text.c)

	if (LWS_WITH_SECURE_STREAMS AND LWS_WITH_CLIENT)
		list(APPEND SOURCES
			misc/dlo/dlo-ss.c)
	endif()

	if (LWS_WITH_UPNG)
		list(APPEND SOURCES
			misc/dlo/dlo-png.c)
	endif()

	if (LWS_WITH_JPEG)
		list(APPEND SOURCES
			misc/dlo/dlo-jpeg.c)
	endif()

	if (LWS_WITH_LHP)
		list(APPEND SOURCES
			misc/dlo/dlo-lhp.c
		)
	endif()

endif()  #dlo

# this is an older, standalone hashed disk cache
# implementation unrelated to lws-cache-ttl
if (LWS_WITH_DISKCACHE)
	list(APPEND SOURCES
		misc/diskcache.c)
endif()

if (LWS_WITH_STRUCT_JSON)
	list(APPEND SOURCES
		misc/lws-struct-lejp.c)
endif()

if (LWS_WITH_JSONRPC)
	list(APPEND SOURCES
		misc/jrpc/jrpc.c)
	include_directories(misc/jrpc)
endif()

if (LWS_WITH_STRUCT_SQLITE3)
	list(APPEND SOURCES
		misc/lws-struct-sqlite.c)
endif()

if (LWS_WITH_FSMOUNT AND ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
	list(APPEND SOURCES misc/fsmount.c)
endif()

if (LWS_WITH_DIR AND NOT LWS_PLAT_BAREMETAL)
	list(APPEND SOURCES misc/dir.c)
endif()

if (LWS_WITH_THREADPOOL AND LWS_HAVE_PTHREAD_H)
	list(APPEND SOURCES misc/threadpool/threadpool.c)
endif()

if (LWS_WITH_PEER_LIMITS)
	list(APPEND SOURCES
		misc/peer-limits.c)
endif()

if (LWS_WITH_LWSAC)
	list(APPEND SOURCES
		misc/lwsac/lwsac.c)
	if (NOT LWS_PLAT_FREERTOS AND NOT LWS_PLAT_BAREMETAL)
		list(APPEND SOURCES
			misc/lwsac/cached-file.c)
	endif()
	if (LWS_WITH_SECURE_STREAMS_CPP)
		list(APPEND SOURCES misc/lwsac/lwsac.cxx)
	endif()
endif()

if (NOT LWS_WITHOUT_BUILTIN_SHA1)
	list(APPEND SOURCES
		misc/sha-1.c)
endif()

if (LWS_WITH_LEJP)
	list(APPEND SOURCES
		misc/lejp.c)
endif()
if (LWS_WITH_CBOR)
	list(APPEND SOURCES
		misc/lecp.c
		misc/ieeehalfprecision.c)
endif()
if (LWS_WITH_LHP)
	list(APPEND SOURCES
		misc/lhp.c)

	if (LWS_WITH_SECURE_STREAMS)
		list(APPEND SOURCES
			misc/lhp-ss.c)
	endif()

endif()

if (UNIX)
	if (NOT LWS_HAVE_GETIFADDRS)
		list(APPEND HDR_PRIVATE misc/getifaddrs.h)
		list(APPEND SOURCES misc/getifaddrs.c)
	endif()
endif()

if (NOT WIN32 AND NOT LWS_WITHOUT_DAEMONIZE)
	list(APPEND SOURCES
		misc/daemonize.c)
endif()

endif()
#
# Keep explicit parent scope exports at end
#

exports_to_parent_scope()
