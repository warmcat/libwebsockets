#
# libwebsockets - small server side websockets and web server implementation
#
# Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
# The sansIO half (READMEs/README.sans-io-split.md): the protocol state
# machines, parsers and framers, the roles that speak a wire protocol, and
# the wsi and vhost lifecycle decisions.  Every source under this directory
# is a sansIO source: they go into the library as ever, and into
# SOURCES_SANSIO, which lib/CMakeLists.txt compiles under the sansIO check
# (LWS_SANSIO_CHECK, an implicit declaration an error).
#
# The strategy is to only export to PARENT_SCOPE
#
#  - changes to LIB_LIST
#  - changes to SOURCES
#  - SOURCES_SANSIO
#  - includes via include_directories
#
# and keep everything else private

include_directories(.)

list(APPEND SOURCES
	sansio/dummy-callback.c
	sansio/close.c
	sansio/output.c
	sansio/vhost.c
	sansio/wsi.c
	sansio/wsi-state.c
)

if (LWS_WITH_SYS_STATE)
	list(APPEND SOURCES
		sansio/state.c
	)
endif()

if (LWS_WITH_CLIENT)
	list(APPEND SOURCES
		sansio/client-connect4.c)
endif()

if (LWS_WITH_SOCKS5 AND NOT LWS_WITHOUT_CLIENT)
	list(APPEND SOURCES
		sansio/socks5-client.c)
endif()

if (LWS_ROLE_MQTT)
	add_subdir_include_directories(mqtt)
endif()

if (LWS_ROLE_QUIC)
	add_subdir_include_directories(quic)
endif()

if (LWS_ROLE_H1 OR LWS_ROLE_H2 OR LWS_ROLE_H3)
	add_subdir_include_directories(http)
endif()

if (LWS_ROLE_H1 OR LWS_ROLE_H2 OR LWS_ROLE_H3)
	add_subdir_include_directories(h1)
endif()

if (LWS_ROLE_H2)
	add_subdir_include_directories(h2)
endif()

if (LWS_ROLE_H3)
	add_subdir_include_directories(h3)
endif()

if (LWS_ROLE_WT)
	add_subdir_include_directories(wt)
endif()

if (LWS_ROLE_WS)
	add_subdir_include_directories(ws)
endif()

if (LWS_ROLE_RAW)
	add_subdir_include_directories(raw-skt)
endif()

if (LWS_ROLE_RAW_PROXY)
	add_subdir_include_directories(raw-proxy)
endif()

if (LWS_WITH_CLIENT AND (LWS_ROLE_H1 OR LWS_ROLE_H2 OR LWS_ROLE_H3 OR LWS_ROLE_QUIC))
	list(APPEND SOURCES
		sansio/http/client/client-http.c
		sansio/http/client/altsvc.c)
endif()

#
# The directory is the list: the sansIO sources are what was added from here
#

set(SOURCES_SANSIO ${SOURCES})
list(FILTER SOURCES_SANSIO INCLUDE REGEX "^sansio/")

#
# Keep explicit parent scope exports at end
#

export_to_parent_intermediate()
set(SOURCES_SANSIO ${SOURCES_SANSIO} PARENT_SCOPE)
