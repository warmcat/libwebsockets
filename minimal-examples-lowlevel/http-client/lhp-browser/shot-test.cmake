#
# ctest driver for the lhp-browser window smoke test
#
# Renders the same document with --bmp and with --gui --shot, and compares
# the results: the window-presented framebuffer must be byte-identical to
# the straight render.
#

#
# cmake -DTOOL=<lws-lhp-browser> -DHTML=<page.html> -DOUT=<shot.bmp>
#       [-DSCROLL=<y> -DVH=<window height>] -P shot-test.cmake
#
# Without SCROLL: the window is a viewport of the same size as the bmp
# surface, so the shot (the window's presented lines) must be identical to
# the first 480 rows of the straight render.
#
# With SCROLL: the gui run scrolls its VH-tall window to y = SCROLL after
# the first render and the shot is the re-scan of the retained DLOs from
# there; it must be identical to rows SCROLL .. SCROLL + VH of a straight
# render laid out at the same 16k height the gui uses
#

if (SCROLL)
	execute_process(COMMAND ${TOOL} file://${HTML} --w 400 --h ${VH}
				--doc-h 16384 --scroll ${SCROLL}
				--bmp ${OUT}-ref.bmp
			RESULT_VARIABLE r OUTPUT_QUIET ERROR_QUIET TIMEOUT 60)
	if (NOT r EQUAL 0)
		message(FATAL_ERROR "${TOOL} --bmp --scroll failed (${r})")
	endif()

	execute_process(COMMAND ${TOOL} file://${HTML} --w 400 --h ${VH}
				--gui --shot ${OUT} --scroll ${SCROLL}
			RESULT_VARIABLE r OUTPUT_QUIET ERROR_QUIET TIMEOUT 60)
	if (NOT r EQUAL 0)
		message(FATAL_ERROR "${TOOL} --gui --shot --scroll failed (${r})")
	endif()

	execute_process(COMMAND ${CMAKE_COMMAND} -E compare_files
				${OUT}-ref.bmp ${OUT}
			RESULT_VARIABLE r)
	if (NOT r EQUAL 0)
		message(FATAL_ERROR "scrolled window shot differs from the --bmp render of the same rows")
	endif()

	file(REMOVE ${OUT}-ref.bmp)
	return()
endif()

execute_process(COMMAND ${TOOL} file://${HTML} --w 400 --h 480
			--bmp ${OUT}-ref.bmp
		RESULT_VARIABLE r OUTPUT_QUIET ERROR_QUIET TIMEOUT 60)
if (NOT r EQUAL 0)
	message(FATAL_ERROR "${TOOL} --bmp failed (${r})")
endif()

execute_process(COMMAND ${TOOL} file://${HTML} --w 400 --h 480
			--gui --shot ${OUT}
		RESULT_VARIABLE r OUTPUT_QUIET ERROR_QUIET TIMEOUT 60)
if (NOT r EQUAL 0)
	message(FATAL_ERROR "${TOOL} --gui --shot failed (${r})")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} -E compare_files ${OUT}-ref.bmp ${OUT}
		RESULT_VARIABLE r)
if (NOT r EQUAL 0)
	message(FATAL_ERROR "window framebuffer shot differs from --bmp render")
endif()

file(REMOVE ${OUT}-ref.bmp)
