#
# ctest driver for one lhp layout case
#
# cmake -DTOOL=<lws-api-test-lhp-dlo> -DHTML=<case.html> -DGOLDEN=<case.dlo>
#       -DOUT=<scratch.dlo> [-DW=400 -DH=300] [-DUPDATE=1] [-DLOCALIZE=1]
#       -P lhp-dlo-case.cmake
#
# Lays out HTML with the tool, dumps the resulting DLO tree as text and
# compares it with GOLDEN.  With UPDATE=1 the golden is overwritten instead,
# for use after an intentional layout change:
#
#   cd build && ctest -R api-test-lhp-dlo- --output-on-failure   # check
#   cmake -DUPDATE=1 ... -P lhp-dlo-case.cmake                    # accept
#

if (NOT W)
	set(W 400)
endif()
if (NOT H)
	set(H 300)
endif()

if (LOCALIZE)
	#
	# A captured page refers to assets on the real network.  Rewrite those
	# references to a local path that does not exist, so the test never
	# touches the network and the (unavailable) assets fail the same way
	# every time.
	#
	file(READ ${HTML} html)
	string(REGEX REPLACE "(href|src)=([\"'])(https?:)?//" "\\1=\\2missing/" html "${html}")
	# the copy lives in the build dir: keep relative references (captured
	# stylesheets, images) pointing at the source directory
	get_filename_component(HD ${HTML} DIRECTORY)
	string(REGEX REPLACE "(href|src)=\"([^\"/:#][^\":]*)\"" "\\1=\"file://${HD}/\\2\"" html "${html}")
	string(REGEX REPLACE "(href|src)=\"/([^\"/][^\":]*)\"" "\\1=\"file://${HD}/\\2\"" html "${html}")
	get_filename_component(HN ${HTML} NAME)
	file(WRITE ${OUT}-${HN} "${html}")
	set(HTML ${OUT}-${HN})
endif()

execute_process(COMMAND ${TOOL} file://${HTML} --w ${W} --h ${H}
			--dump ${OUT} -d 3
		RESULT_VARIABLE r OUTPUT_QUIET ERROR_QUIET TIMEOUT 30)
if (NOT r EQUAL 0)
	message(FATAL_ERROR "${TOOL} failed (${r}) on ${HTML}")
endif()

if (UPDATE)
	configure_file(${OUT} ${GOLDEN} COPYONLY)
	message("updated ${GOLDEN}")
	return()
endif()

execute_process(COMMAND ${CMAKE_COMMAND} -E compare_files ${GOLDEN} ${OUT}
		RESULT_VARIABLE r)
if (NOT r EQUAL 0)
	find_program(DIFF diff)
	if (DIFF)
		execute_process(COMMAND ${DIFF} -u ${GOLDEN} ${OUT})
	endif()
	message(FATAL_ERROR "layout of ${HTML} differs from ${GOLDEN}")
endif()
