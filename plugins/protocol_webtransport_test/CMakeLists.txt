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

set(PLUGIN_NAME "protocol_webtransport_test")
set(PLUGIN_SRCS protocol_webtransport_test.c)

set(requirements 1)
require_lws_config(LWS_ROLE_WT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	create_plugin(${PLUGIN_NAME} "" ${PLUGIN_SRCS} "" "")
	
	if (NOT LWS_WITH_PLUGINS_BUILTIN)
		target_compile_definitions(${PLUGIN_NAME} PRIVATE LWS_BUILDING_SHARED)
	endif()
endif()
