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

include_directories(.)

# what neither half owns (READMEs/README.sans-io-split.md): the halves are
# lib/sansio and lib/io
list(APPEND SOURCES
	core-net/txpacer.c
	core-net/async-queue.c
	core-net/roles.c
)

if (LWS_WITH_LATENCY)
	list(APPEND SOURCES
		core-net/latency.c
	)
endif()

if (LWS_WITH_STUB AND NOT LWS_WITHOUT_CLIENT)
	list(APPEND SOURCES
		core-net/stub.c
	)
endif()

if (NOT LWS_WITHOUT_CLIENT)
	list(APPEND SOURCES
		core-net/async-ipc.c
	)
endif()


if (LWS_WITH_TRANSPORT_SEQUENCER)
	list(APPEND SOURCES
		core-net/lws-transport-sequencer.c
	)
endif()


if (LWS_WITH_LWS_DSH)
	list(APPEND SOURCES
		core-net/lws-dsh.c)
endif()

if (LWS_WITH_WOL)
	list(APPEND SOURCES
		core-net/wol.c)
endif()

if (LWS_WITH_CLIENT)
	list(APPEND SOURCES
		core-net/client/client.c
		)
endif()

if (LWS_WITH_WEBRTC)
	list(APPEND SOURCES
		core-net/lws-rtp.c
		core-net/lws-srtp.c
		core-net/lws-stun.c
	)
endif()

exports_to_parent_scope()
