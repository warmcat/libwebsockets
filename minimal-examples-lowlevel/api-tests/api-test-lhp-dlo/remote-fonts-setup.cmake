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

# A server making pages from .ttf lists most faces' pages as runs, like
# "0000-0005,0020": list these faces' pages that way too, so a device has to
# parse a run to get them at all.  The text in the tests has nothing on page
# 0001, so nothing asks for it.

file(READ ${OUT}/faces/fonts.json J)
string(REPLACE "\"pages\":\"0000," "\"pages\":\"0000-0001," J2 "${J}")
if (J2 STREQUAL J)
	message(FATAL_ERROR "the font manifest has no faces with page 0000")
endif()
file(WRITE ${OUT}/faces/fonts.json "${J2}")

file(MAKE_DIRECTORY ${OUT}/nofaces)
file(COPY ${OUT}/faces/fonts.json DESTINATION ${OUT}/nofaces)

file(COPY ${OUT}/faces/ DESTINATION ${OUT}/nopunct)
file(GLOB PUNCT ${OUT}/nopunct/*/*/0020.mcufont)
if (NOT PUNCT)
	message(FATAL_ERROR "no face has a page 0020")
endif()
file(REMOVE ${PUNCT})
