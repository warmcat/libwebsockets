#
# lhp-browser unix window backend (X11)
#
# add_subdirectory()'d from the app CMakeLists when the host looks unix-y.
# This file decides if the backend's requirements are present, and if so
# exports to the parent scope how to build and link it.  If they are not,
# the app is not built at all.
#
# Xi (XInput2) is needed for touchpad smooth-scrolling valuator events.
#

find_package(X11 QUIET COMPONENTS Xi)

if (NOT X11_FOUND OR NOT X11_Xi_FOUND)
	message(STATUS "lhp-browser: plat/unix needs X11 dev headers and libXi, not found")
	set(LHP_BROWSER_PLAT_OK 0 PARENT_SCOPE)

	return()
endif()

message(STATUS "lhp-browser: plat/unix X11 window backend enabled")

set(LHP_BROWSER_PLAT_OK  1 PARENT_SCOPE)
set(LHP_BROWSER_PLAT_SRC ${CMAKE_CURRENT_LIST_DIR}/unix.c PARENT_SCOPE)
set(LHP_BROWSER_PLAT_DEFS LHP_BROWSER_HAVE_BACKEND=1 PARENT_SCOPE)
set(LHP_BROWSER_PLAT_INC ${X11_INCLUDE_DIR} PARENT_SCOPE)
set(LHP_BROWSER_PLAT_LIBS ${X11_LIBRARIES} ${X11_Xi_LIB} PARENT_SCOPE)
