#
# ctest fixture: a directory to serve fonts from, as a server would
#
# cmake -DFONTS=<dir of .mcufont> -DMANIFEST_TOOL=<fonts-manifest.cmake>
#       -DOUT=<scratch dir> -P remote-fonts-setup.cmake
#
# <OUT>/faces/ gets the .mcufont files and their fonts.json, and
# <OUT>/nofaces/ the same fonts.json with none of the faces beside it.
#

file(REMOVE_RECURSE ${OUT})
file(MAKE_DIRECTORY ${OUT}/faces ${OUT}/nofaces)
file(GLOB FACES ${FONTS}/*.mcufont)
file(COPY ${FACES} DESTINATION ${OUT}/faces)

execute_process(COMMAND ${CMAKE_COMMAND} -DDIR=${OUT}/faces
				-DOUT=${OUT}/faces/fonts.json
				-P ${MANIFEST_TOOL}
		RESULT_VARIABLE r)
if (NOT r EQUAL 0)
	message(FATAL_ERROR "making the font manifest failed")
endif()

file(COPY ${OUT}/faces/fonts.json DESTINATION ${OUT}/nofaces)
