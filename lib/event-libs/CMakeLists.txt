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

#
# These can coexist, except libev conflicts with libevent
#

if (LWS_WITH_POLL)
	add_subdir_include_directories(poll)
endif()

if (LWS_WITH_LIBUV)
	add_subdir_include_directories(libuv)
	set(LWS_HAVE_UV_VERSION_H ${LWS_HAVE_UV_VERSION_H} PARENT_SCOPE)
	set(LWS_HAVE_NEW_UV_VERSION_H ${LWS_HAVE_NEW_UV_VERSION_H} PARENT_SCOPE)
endif()

if (LWS_WITH_LIBEVENT)
	add_subdir_include_directories(libevent)
endif()

if (LWS_WITH_GLIB)
	add_subdir_include_directories(glib)
endif()

if (LWS_WITH_LIBEV)
	add_subdir_include_directories(libev)
	set(LWS_HAVE_EVBACKEND_LINUXAIO ${LWS_HAVE_EVBACKEND_LINUXAIO} PARENT_SCOPE)
	set(LWS_HAVE_EVBACKEND_IOURING ${LWS_HAVE_EVBACKEND_IOURING} PARENT_SCOPE)
endif()

#
# Keep explicit parent scope exports at end
#

export_to_parent_intermediate()
