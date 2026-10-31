#
# ctest fixture: a directory to serve fonts from, as a server would
#
# cmake -DFONTS=<dir of .mcufont> -DMANIFEST_TOOL=<fonts-manifest.cmake>
#       -DOUT=<scratch dir> -P remote-fonts-setup.cmake
#
# <OUT>/faces/ gets the faces' pages and their fonts.json, <OUT>/nofaces/
# the same fonts.json with none of the pages beside it, and
# <OUT>/nopunct/ the same again but without any face's page 0020, the
# page with the dashes and quotes on.
#

file(REMOVE_RECURSE ${OUT})

execute_process(COMMAND ${CMAKE_COMMAND} -DDIR=${FONTS}
				-DOUT=${OUT}/faces
				-P ${MANIFEST_TOOL}
		RESULT_VARIABLE r)
if (NOT r EQUAL 0)
	message(FATAL_ERROR "making the font manifest failed")
endif()

file(MAKE_DIRECTORY ${OUT}/nofaces)
file(COPY ${OUT}/faces/fonts.json DESTINATION ${OUT}/nofaces)

file(COPY ${OUT}/faces/ DESTINATION ${OUT}/nopunct)
file(GLOB_RECURSE PUNCT ${OUT}/nopunct/*/0020.mcufont)
file(REMOVE ${PUNCT})
