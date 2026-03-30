#
# libwebsockets - small server side websockets and web server implementation
#
# Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

include_directories(${LWS_LIB_BUILD_INC_PATHS})

SUBDIRLIST(SUBDIRS "${PROJECT_SOURCE_DIR}/minimal-examples")

FOREACH(subdir ${SUBDIRS})

	SUBDIRLIST(SUBDIRS2 "${PROJECT_SOURCE_DIR}/minimal-examples/${subdir}")
	FOREACH(subdir2 ${SUBDIRS2})
		if (EXISTS "${PROJECT_SOURCE_DIR}/minimal-examples/${subdir}/${subdir2}/CMakeLists.txt")
			set(MINIMAL_REJECTED 0)

			if (NOT "${LWS_WITH_MINIMAL_FILTER_NO}" STREQUAL "")
				string(REPLACE "," ";" NO_LIST "${LWS_WITH_MINIMAL_FILTER_NO}")
				foreach(P ${NO_LIST})
					if ("${subdir2}" MATCHES "${P}")
						set(MINIMAL_REJECTED 1)
					endif()
				endforeach()
			endif()

			if (NOT MINIMAL_REJECTED AND NOT "${LWS_WITH_MINIMAL_FILTER_YES}" STREQUAL "")
				set(FOUND_YES 0)
				string(REPLACE "," ";" YES_LIST "${LWS_WITH_MINIMAL_FILTER_YES}")
				foreach(P ${YES_LIST})
					if ("${subdir2}" MATCHES "${P}")
						set(FOUND_YES 1)
					endif()
				endforeach()
				if (NOT FOUND_YES)
					set(MINIMAL_REJECTED 1)
				endif()
			endif()

			if (NOT MINIMAL_REJECTED)
				message("Processing ${PROJECT_SOURCE_DIR}/minimal-examples/${subdir}/${subdir2}")
				add_subdirectory("${PROJECT_SOURCE_DIR}/minimal-examples/${subdir}/${subdir2}")
			else()
				message(STATUS "Skipping minimal example ${subdir2} due to filter")
			endif()
		endif()
	ENDFOREACH()
ENDFOREACH()
