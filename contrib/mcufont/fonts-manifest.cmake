#
# Make the font manifest for a directory of .mcufont files
#
# cmake -DDIR=<dir of .mcufont> -DOUT=<fonts.json> -P fonts-manifest.cmake
#
# A device that registers the manifest with lws_fonts_register_manifest()
# learns the faces from it, and fetches each one from beside the manifest
# when text needs it.  Put the generated fonts.json in the same directory
# as the .mcufont files on the server.  For each face it gives the name the
# chooser matches css font-family against (the face's mcufont full name),
# its line height, and its size, all of which the device checks against
# the face when it arrives.
#

if (NOT DIR OR NOT OUT)
	message(FATAL_ERROR "use: cmake -DDIR=<dir> -DOUT=<fonts.json> -P fonts-manifest.cmake")
endif()

# the big-endian unsigned at byte ofs of the hex dump h (by hand: math()
# only takes hex from cmake 3.13)

function(mcuf_be h ofs bytes var)
	math(EXPR o "${ofs} * 2")
	math(EXPR n "${bytes} * 2")
	string(SUBSTRING "${h}" ${o} ${n} x)
	set(v 0)
	foreach(i RANGE 1 ${n})
		string(SUBSTRING "${x}" 0 1 c)
		string(SUBSTRING "${x}" 1 -1 x)
		string(FIND "0123456789abcdef" "${c}" d)
		math(EXPR v "${v} * 16 + ${d}")
	endforeach()
	set(${var} ${v} PARENT_SCOPE)
endfunction()

get_filename_component(DIR ${DIR} ABSOLUTE)
file(GLOB FACES RELATIVE ${DIR} ${DIR}/*.mcufont)
list(SORT FACES)

set(J "{\"fonts\":[")
set(SEP "")

foreach(F ${FACES})
	file(READ ${DIR}/${F} H HEX)
	string(LENGTH "${H}" L)
	math(EXPR L "${L} / 2")

	if (L LESS 64 OR NOT H MATCHES "^4d435546")
		message(FATAL_ERROR "${F} is not an mcufont")
	endif()

	# the full name, a NUL-terminated string at the offset in the header

	mcuf_be("${H}" 8 4 NO)
	set(NAME "")
	set(I ${NO})
	while (1)
		if (NOT I LESS L)
			message(FATAL_ERROR "${F}: name runs off the end")
		endif()
		mcuf_be("${H}" ${I} 1 C)
		if (C EQUAL 0)
			break()
		endif()
		if (C LESS 32 OR C GREATER 126 OR C EQUAL 34 OR C EQUAL 92)
			message(FATAL_ERROR "${F}: name has a character we don't put in json")
		endif()
		string(ASCII ${C} CH)
		string(APPEND NAME "${CH}")
		math(EXPR I "${I} + 1")
	endwhile()

	mcuf_be("${H}" 60 2 LH)

	string(APPEND J "${SEP}\n  {\"name\":\"${NAME}\",\"file\":\"${F}\",\"line_height\":${LH},\"len\":${L}}")
	set(SEP ",")
endforeach()

string(APPEND J "\n]}\n")
file(WRITE ${OUT} "${J}")
