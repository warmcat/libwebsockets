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

# makes pages of faces by spawning lws-mcufont-encoder, into an lws_diskcache

set(PLUGIN_NAME protocol_lws_mcufonts)
set(requirements 1)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_SPAWN 1 requirements)
require_lws_config(LWS_WITH_DISKCACHE 1 requirements)
require_lws_config(LWS_WITH_STRUCT_JSON 1 requirements)

if (requirements AND NOT WIN32)
	create_plugin(${PLUGIN_NAME} "" "protocol_lws_mcufonts.c" "" "")
	if (NOT LWS_WITH_PLUGINS_BUILTIN)
		target_compile_definitions(${PLUGIN_NAME} PRIVATE LWS_BUILDING_SHARED)
	endif()
endif()
