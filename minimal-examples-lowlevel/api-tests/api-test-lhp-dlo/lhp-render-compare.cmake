#
# ctest driver: render one page twice and require identical output
#
# cmake -DTOOL=<lws-api-test-lhp-dlo> -DHTML=<page.html> -DOUT=<scratch prefix>
#       [-DHTML_B=<page.html>] [-DW=600 -DH=448] [-DFLAGS_A=<switches>]
#       [-DFLAGS_B=<switches>] [-DCOMMON=<switches for both>]
#       -P lhp-render-compare.cmake
#
# The page is rendered to a .bmp with FLAGS_A and again with FLAGS_B, each
# getting its own empty asset cache, and the two renders must be byte for
# byte the same.  Used to show that a render under memory pressure, with
# fonts and images evicted and renewed along the way, comes out as it would
# with everything resident.
#
# With HTML_B, the second render is of that page instead, eg, the same
# images in another encoding that must come out the same.
#

if (NOT W)
	set(W 600)
endif()
if (NOT H)
	set(H 448)
endif()
set(HTML_A ${HTML})
if (NOT HTML_B)
	set(HTML_B ${HTML})
endif()

foreach(SIDE A B)
	set(CACHE_DIR "${OUT}-cache-${SIDE}")
	file(REMOVE_RECURSE ${CACHE_DIR})
	file(REMOVE ${OUT}-${SIDE}.bmp)

	execute_process(COMMAND ${TOOL} file://${HTML_${SIDE}} --w ${W} --h ${H}
				${COMMON} ${FLAGS_${SIDE}}
				--asset-cache ${CACHE_DIR}
				--bmp ${OUT}-${SIDE}.bmp -d 3
			RESULT_VARIABLE r OUTPUT_QUIET ERROR_QUIET TIMEOUT 60)
	file(REMOVE_RECURSE ${CACHE_DIR})
	if (NOT r EQUAL 0)
		message(FATAL_ERROR "${TOOL} failed (${r}) rendering ${HTML_${SIDE}} (${SIDE})")
	endif()
endforeach()

execute_process(COMMAND ${CMAKE_COMMAND} -E compare_files
			${OUT}-A.bmp ${OUT}-B.bmp
		RESULT_VARIABLE r)
if (NOT r EQUAL 0)
	message(FATAL_ERROR "render of ${HTML_A} ${FLAGS_A} differs from ${HTML_B} ${FLAGS_B}")
endif()
