project(lws-minimal-http-server-systemd-socketact C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SRCS minimal-http-server-systemd-socketact.c)

add_compile_options(-Wall -Wextra -Werror -pedantic -g -Ofast
                    -DINSTALL_SHARE=\"${CMAKE_INSTALL_PREFIX}/share/${PROJECT_NAME}\")

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_HAVE_SYSTEMD_H 1 requirements)
require_lws_config(LWS_WITH_SDEVENT 1 requirements)


if (requirements)
	add_executable(${PROJECT_NAME} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME}	websockets_shared
							${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME}	websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME}	websockets
							${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	install(TARGETS ${PROJECT_NAME}
		DESTINATION bin)

	install(FILES   mount-origin/404.html
			mount-origin/favicon.ico
			mount-origin/index.html
			mount-origin/libwebsockets.org-logo.svg
			mount-origin/strict-csp.svg
		DESTINATION share/${PROJECT_NAME})

	install(FILES	lws-minimal-http-server-systemd-socketact.service
			lws-minimal-http-server-systemd-socketact.socket
		DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)

endif()
