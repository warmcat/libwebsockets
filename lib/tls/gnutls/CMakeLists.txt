#
# libwebsockets - small server side websockets and web server implementation
#
# Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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

set(LWS_GNUTLS_LIBRARIES CACHE PATH "Path to the GnuTLS library")
set(LWS_GNUTLS_INCLUDE_DIRS CACHE PATH "Path to the GnuTLS include directory")

if ("${LWS_GNUTLS_LIBRARIES}" STREQUAL "" OR "${LWS_GNUTLS_INCLUDE_DIRS}" STREQUAL "")
	include (FindPkgConfig)
	PKG_SEARCH_MODULE(GNUTLS gnutls)
	if (GNUTLS_FOUND)
		set(GNUTLS_LIBRARIES ${GNUTLS_LIBRARIES} PARENT_SCOPE)
		set(GNUTLS_INCLUDE_DIRS ${GNUTLS_INCLUDE_DIRS} PARENT_SCOPE)
		set(GNUTLS_FOUND ${GNUTLS_FOUND} PARENT_SCOPE)
	endif()
else()
	set(GNUTLS_LIBRARIES ${LWS_GNUTLS_LIBRARIES} PARENT_SCOPE)
	set(GNUTLS_INCLUDE_DIRS ${LWS_GNUTLS_INCLUDE_DIRS} PARENT_SCOPE)
	set(GNUTLS_FOUND 1 PARENT_SCOPE)
	set(GNUTLS_FOUND 1)
endif()

if (GNUTLS_FOUND)
	list(APPEND LIB_LIST ${GNUTLS_LIBRARIES})
	set(LIB_LIST ${LIB_LIST} PARENT_SCOPE)
	include_directories(${GNUTLS_INCLUDE_DIRS})
	set(LWS_WITH_GNUTLS 1 PARENT_SCOPE)
endif()

exports_to_parent_scope()
