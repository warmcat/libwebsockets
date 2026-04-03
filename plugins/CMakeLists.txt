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

include_directories(.)
include(LwsCheckRequirements)

if (DEFINED LIB_LIST_AT_END)
link_libraries(${LIB_LIST_AT_END})
endif()

MACRO(SUBDIRLIST result curdir)
  FILE(GLOB children RELATIVE ${curdir} ${curdir}/*)
  SET(dirlist "")

  FOREACH(child ${children})
    IF (IS_DIRECTORY ${curdir}/${child})
	LIST(APPEND dirlist ${child})
    ENDIF()
  ENDFOREACH()

  SET(${result} ${dirlist})
ENDMACRO()

if ((LWS_WITH_PLUGINS AND LWS_WITH_SHARED) OR LWS_WITH_PLUGINS_BUILTIN)

	#
	# Either build the plugins as separate dynamic libs (LWS_WITH_PLUGINS)
	# or build into the main lws library (LWS_WITH_PLUGINS_BUILTIN)
	#

	macro(create_plugin PLUGIN_NAME PLUGIN_INCLUDE MAIN_SRC S2 S3)
		set(PLUGIN_REJECTED 0)

		if (NOT "${LWS_WITH_PLUGIN_FILTER_NO}" STREQUAL "")
			string(REPLACE "," ";" NO_LIST "${LWS_WITH_PLUGIN_FILTER_NO}")
			foreach(P ${NO_LIST})
				if ("${PLUGIN_NAME}" MATCHES "${P}")
					set(PLUGIN_REJECTED 1)
				endif()
			endforeach()
		endif()

		if (NOT PLUGIN_REJECTED AND NOT "${LWS_WITH_PLUGIN_FILTER_YES}" STREQUAL "")
			set(FOUND_YES 0)
			string(REPLACE "," ";" YES_LIST "${LWS_WITH_PLUGIN_FILTER_YES}")
			foreach(P ${YES_LIST})
				if ("${PLUGIN_NAME}" MATCHES "${P}")
					set(FOUND_YES 1)
				endif()
			endforeach()
			if (NOT FOUND_YES)
				set(PLUGIN_REJECTED 1)
			endif()
		endif()

		if (PLUGIN_REJECTED)
			message(STATUS "Skipping plugin ${PLUGIN_NAME} due to filter")
			return()
		endif()

		if (NOT LWS_WITH_PLUGINS_BUILTIN)
			set(PLUGIN_SRCS "")
			foreach(A ${MAIN_SRC})
				if (IS_ABSOLUTE ${A})
					list(APPEND PLUGIN_SRCS ${A})
				else()
					list(APPEND PLUGIN_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/${A})
				endif()
			endforeach()

			if (NOT "${S2}" STREQUAL "")
				foreach(A ${S2})
					if (IS_ABSOLUTE ${A})
						list(APPEND PLUGIN_SRCS ${A})
					else()
						list(APPEND PLUGIN_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/${A})
					endif()
				endforeach()
			endif()
			if (NOT "${S3}" STREQUAL "")
				foreach(A ${S3})
					if (IS_ABSOLUTE ${A})
						list(APPEND PLUGIN_SRCS ${A})
					else()
						list(APPEND PLUGIN_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/${A})
					endif()
				endforeach()
			endif()

			if (WIN32)
				list(APPEND PLUGIN_SRCS
					${WIN32_HELPERS_PATH}/getopt.c
					${WIN32_HELPERS_PATH}/getopt_long.c
					${WIN32_HELPERS_PATH}/gettimeofday.c
				)

				list(APPEND PLUGIN_HDR
					${WIN32_HELPERS_PATH}/getopt.h
					${WIN32_HELPERS_PATH}/gettimeofday.h
				)
			endif(WIN32)

			source_group("Headers Private"   FILES ${PLUGIN_HDR})
			source_group("Sources"   FILES ${PLUGIN_SRCS})
			add_library(${PLUGIN_NAME} SHARED ${PLUGIN_SRCS} ${PLUGIN_HDR})
			target_link_libraries(${PLUGIN_NAME} websockets_shared)
			add_dependencies(${PLUGIN_NAME} websockets_shared)

			# doesn't work inside macro :-O
			# target_compile_definitions(${PLUGIN_NAME} PRIVATE LWS_BUILDING_SHARED)
			target_include_directories(${PLUGIN_NAME} PRIVATE ${PLUGIN_INCLUDE}
									  ${LWS_LIB_BUILD_INC_PATHS})
			set_property(TARGET ${PLUGIN_NAME}
				     PROPERTY COMPILE_DEFINITIONS
				     INSTALL_DATADIR="${CMAKE_INSTALL_PREFIX}/plugins"
			)

			set(CMAKE_POSITION_INDEPENDENT_CODE ON)
			list(APPEND PLUGINS_LIST ${PLUGIN_NAME})
			set(PLUGINS_LIST ${PLUGINS_LIST} PARENT_SCOPE)
		else()
			# let's just build the things into the lib

			message("Building in plugin ${PLUGIN_NAME}")
			list(APPEND LWS_BUILTIN_PLUGIN_NAMES "${PLUGIN_NAME}")
			set(LWS_BUILTIN_PLUGIN_NAMES ${LWS_BUILTIN_PLUGIN_NAMES} PARENT_SCOPE)

			if (NOT "${PLUGIN_INCLUDE}" STREQUAL "")
				if (IS_ABSOLUTE ${PLUGIN_INCLUDE})
					list(APPEND LWS_LIB_BUILD_INC_PATHS ${PLUGIN_INCLUDE})
				else()
					list(APPEND LWS_LIB_BUILD_INC_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/${PLUGIN_INCLUDE})
				endif()
				set(LWS_LIB_BUILD_INC_PATHS ${LWS_LIB_BUILD_INC_PATHS} PARENT_SCOPE)
			endif()

			if (NOT "${MAIN_SRC}" STREQUAL "")
				foreach(A ${MAIN_SRC})
					if (IS_ABSOLUTE ${A})
						list(APPEND SOURCES ${A})
					else()
						list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${A})
					endif()
				endforeach()
			endif()
			if (NOT "${S2}" STREQUAL "")
				foreach(A ${S2})
					if (IS_ABSOLUTE ${A})
						list(APPEND SOURCES ${A})
					else()
						list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${A})
					endif()
				endforeach()
			endif()
			if (NOT "${S3}" STREQUAL "")
				foreach(A ${S3})
					if (IS_ABSOLUTE ${A})
						list(APPEND SOURCES ${A})
					else()
						list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${A})
					endif()
				endforeach()
			endif()

			set(SOURCES ${SOURCES} PARENT_SCOPE)
		endif(NOT LWS_WITH_PLUGINS_BUILTIN)
	endmacro()

	SUBDIRLIST(SUBDIRS "${CMAKE_CURRENT_SOURCE_DIR}")
	FOREACH(subdir ${SUBDIRS})
		if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${subdir}/CMakeLists.txt")
			message("Processing ${CMAKE_CURRENT_SOURCE_DIR}/${subdir}")
			add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/${subdir}")
		endif()
	ENDFOREACH()

endif((LWS_WITH_PLUGINS AND LWS_WITH_SHARED) OR LWS_WITH_PLUGINS_BUILTIN)


# plugins

if (LWS_WITH_PLUGINS AND NOT LWS_WITH_PLUGINS_BUILTIN)
	if (PLUGINS_LIST)
		install(TARGETS ${PLUGINS_LIST}
			PERMISSIONS  OWNER_WRITE OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE OWNER_READ GROUP_READ WORLD_READ
			DESTINATION "${LWS_INSTALL_PLUGIN_DIR}"
			COMPONENT plugins)
	endif()
endif()

export_to_parent_intermediate()
