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
# The IO half (READMEs/README.sans-io-split.md): moving bytes, fds, poll and
# timers, the client's dns and connect, and the transport adapter roles that
# wear the role interface but own nothing on the wire.  lib/tls, lib/plat,
# lib/event-libs and lib/system/async-dns are IO's too, by their directories.
#
# The strategy is to only export to PARENT_SCOPE
#
#  - changes to LIB_LIST
#  - changes to SOURCES
#  - includes via include_directories
#
# and keep everything else private

include_directories(.)

list(APPEND SOURCES
	io/output.c
	io/network.c
	io/vhost.c
	io/pollfd.c
	io/service.c
	io/sorted-usec-list.c
	io/wsi-timeout.c
	io/adopt.c
	io/pipe/ops-pipe.c
)

# lwsws' config: the vhosts and mounts it describes are made here
if (LWS_WITH_LEJP_CONF AND LWS_WITH_NETWORK AND NOT LWS_PLAT_OPTEE)
	list(APPEND SOURCES
		io/lejp-conf.c
	)
endif()

if (LWS_WITH_ROUTING)
	list(APPEND SOURCES
		io/route.c
	)
endif()

if (LWS_WITH_CLIENT)
	list(APPEND SOURCES
		io/client/connect.c
		io/client/connect2.c
		io/client/connect3.c
		io/client/transport.c
		io/client/sort-dns.c
		)
	if (LWS_WITH_CONMON)
		list(APPEND SOURCES
			io/client/conmon.c
		)
	endif()
endif()

if (LWS_ROLE_DBUS AND NOT LWS_PLAT_FREERTOS)
	add_subdir_include_directories(dbus)
endif()

if (LWS_ROLE_RAW_FILE)
	add_subdir_include_directories(raw-file)
endif()

if (LWS_WITH_CGI)
	add_subdir_include_directories(cgi)
endif()

if (NOT LWS_WITHOUT_SERVER OR LWS_WITH_SECURE_STREAMS_PROCESS_API)
	add_subdir_include_directories(listen)
endif()

if (LWS_WITH_NETLINK)
	list(APPEND SOURCES io/netlink/ops-netlink.c)
endif()

#
# Keep explicit parent scope exports at end
#

export_to_parent_intermediate()
set(LWS_DEP_LIB_PATHS ${LWS_DEP_LIB_PATHS} PARENT_SCOPE)
