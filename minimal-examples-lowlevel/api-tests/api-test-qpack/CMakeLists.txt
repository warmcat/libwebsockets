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

MACRO(require_lws_config reqconfig _val result)

	if (DEFINED ${reqconfig})
	if (${reqconfig})
		set (rq 1)
	else()
		set (rq 0)
	endif()
	else()
		set(rq 0)
	endif()

	if (${_val} EQUAL ${rq})
		set(SAME 1)
	else()
		set(SAME 0)
	endif()

	if (LWS_WITH_MINIMAL_EXAMPLES AND NOT ${SAME})
		if (${_val})
			message("${SAMP}: skipping as lws being built without ${reqconfig}")
		else()
			message("${SAMP}: skipping as lws built with ${reqconfig}")
		endif()
		set(${result} 0)
	else()
		if (LWS_WITH_MINIMAL_EXAMPLES)
			set(MET ${SAME})
		else()
			set(MET 0)
		endif()
	endif()
ENDMACRO()

set(SAMP lws-api-test-qpack)
set(SRCS main.c)
set(requirements 1)

require_lws_config(LWS_WITH_HTTP3 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)

if (requirements)
	if (LWS_WITH_LS_QPACK)
		find_path(LSQPACK_INCLUDE_DIR NAMES lsqpack.h)
		find_library(LSQPACK_LIBRARY NAMES ls-qpack)
		if (LSQPACK_INCLUDE_DIR AND LSQPACK_LIBRARY)
			message("api-test-qpack: using ls-qpack at ${LSQPACK_LIBRARY}")
			include_directories(${LSQPACK_INCLUDE_DIR})
		else()
			message(FATAL_ERROR "LWS_WITH_LS_QPACK enabled but ls-qpack not found")
		endif()
	endif()

	add_executable(${SAMP} ${SRCS})
	add_dependencies(${SAMP} websockets_shared)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		if (LWS_WITH_LS_QPACK)
			target_link_libraries(${SAMP} ${LSQPACK_LIBRARY})
		endif()
		add_dependencies(${SAMP} websockets_shared)
		target_compile_definitions(${SAMP} PRIVATE LWS_BUILDING_SHARED)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
		if (LWS_WITH_LS_QPACK)
			target_link_libraries(${SAMP} ${LSQPACK_LIBRARY})
		endif()
	endif()
endif()
