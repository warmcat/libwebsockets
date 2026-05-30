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

set(PLUGIN_NAME "protocol_webtransport_shared_world")
set(PLUGIN_SRCS protocol_webtransport_shared_world.c)

set(requirements 1)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	create_plugin(${PLUGIN_NAME} "" ${PLUGIN_SRCS} "" "")
	
	if (NOT LWS_WITH_PLUGINS_BUILTIN)
		target_compile_definitions(${PLUGIN_NAME} PRIVATE LWS_BUILDING_SHARED)
	endif()
	
	if (NOT WIN32 AND LWS_WITH_PLUGINS AND NOT LWS_WITH_PLUGINS_BUILTIN)
		install(FILES assets/index.html assets/app2.js assets/style.css assets/babylon.js assets/dummy3.babylon DESTINATION share/libwebsockets-test-server/shared-world COMPONENT plugins)
	endif()
endif()
