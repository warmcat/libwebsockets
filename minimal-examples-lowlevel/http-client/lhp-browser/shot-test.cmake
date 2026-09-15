#
# ctest driver for the lhp-browser window smoke test
#
# Renders the same document with --bmp and with --gui --shot, and compares
# the results: the window-presented framebuffer must be byte-identical to
# the straight render.
#

#
# The window is a viewport of the same size as the bmp surface: with no
# --h, the gui run lays the document out to its natural height in a
# 480-line window, so the shot (the window's presented lines) must be
# identical to the first 480 rows of the straight render
#

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
