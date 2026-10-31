#
# Lay out a directory of whole .mcufont faces to be served as a server
# serves faces a page at a time, with the manifest listing them
#
# cmake -DDIR=<dir of .mcufont> -DOUT=<dir to serve> -P fonts-manifest.cmake
#
# A device that registers <OUT>/fonts.json with lws_fonts_register_manifest()
# learns the faces from it, and fetches each page of a face from beside the
# manifest when text needs it: <OUT>/<face>/<page>.mcufont, page being four
# hex digits, the codepoints from page * 256.  For each face the manifest
# gives the name the chooser matches css font-family against (the face's
# mcufont full name), its line height and the pages it has, all of which the
# device checks against each page when it arrives.
#
# The pages here are each the whole face, copied for each page its glyphs
# are on, which is fine for faces with glyphs on only a page or two, like
# the ones in contrib/mcufont/fonts.  plugins/protocol_lws_mcufonts makes
# the pages of each face from a .ttf instead, as they are first asked for.
#

if (NOT DIR OR NOT OUT)
	message(FATAL_ERROR "use: cmake -DDIR=<dir> -DOUT=<dir> -P fonts-manifest.cmake")
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

# n as four hex digits

function(mcuf_hex4 n var)
	set(r "")
	foreach(i RANGE 1 4)
		math(EXPR d "${n} % 16")
		math(EXPR n "${n} / 16")
		string(SUBSTRING "0123456789abcdef" ${d} 1 c)
		set(r "${c}${r}")
	endforeach()
	set(${var} ${r} PARENT_SCOPE)
endfunction()

get_filename_component(DIR ${DIR} ABSOLUTE)
file(GLOB FACES RELATIVE ${DIR} ${DIR}/*.mcufont)
list(SORT FACES)
file(MAKE_DIRECTORY ${OUT})

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

	# the pages the face's char ranges cover, in order

	mcuf_be("${H}" 36 4 RO)
	mcuf_be("${H}" 40 4 RN)
	math(EXPR RE "${RO} + ${RN} * 16")
	if (RN EQUAL 0 OR RE GREATER L)
		message(FATAL_ERROR "${F}: bad char range tables")
	endif()

	set(PAGES "")
	math(EXPR RN "${RN} - 1")
	foreach(R RANGE ${RN})
		math(EXPR O "${RO} + ${R} * 16")
		mcuf_be("${H}" ${O} 4 FIRST)
		math(EXPR O "${O} + 4")
		mcuf_be("${H}" ${O} 4 COUNT)
		math(EXPR P0 "${FIRST} / 256")
		math(EXPR P1 "(${FIRST} + ${COUNT} - 1) / 256")
		foreach(P RANGE ${P0} ${P1})
			list(APPEND PAGES ${P})
		endforeach()
	endforeach()
	list(REMOVE_DUPLICATES PAGES)
	list(SORT PAGES COMPARE NATURAL)

	# a copy of the face for each page, and the pages as hex runs

	string(REGEX REPLACE "\\.mcufont$" "" FACE "${F}")
	file(MAKE_DIRECTORY ${OUT}/${FACE})

	set(PS "")
	set(RUN_FIRST -1)
	set(RUN_LAST -1)
	foreach(P ${PAGES} END)
		if (NOT P STREQUAL "END")
			mcuf_hex4(${P} PH)
			configure_file(${DIR}/${F} ${OUT}/${FACE}/${PH}.mcufont COPYONLY)
			math(EXPR NEXT "${RUN_LAST} + 1")
			if (RUN_FIRST GREATER -1 AND P EQUAL NEXT)
				set(RUN_LAST ${P})
				continue()
			endif()
		endif()
		if (RUN_FIRST GREATER -1)
			mcuf_hex4(${RUN_FIRST} A)
			if (PS)
				string(APPEND PS ",")
			endif()
			string(APPEND PS "${A}")
			if (RUN_LAST GREATER RUN_FIRST)
				mcuf_hex4(${RUN_LAST} B)
				string(APPEND PS "-${B}")
			endif()
		endif()
		set(RUN_FIRST ${P})
		set(RUN_LAST ${P})
	endforeach()

	string(APPEND J "${SEP}\n  {\"name\":\"${NAME}\",\"path\":\"${FACE}\",\"line_height\":${LH},\"pages\":\"${PS}\"}")
	set(SEP ",")
endforeach()

string(APPEND J "\n]}\n")
file(WRITE ${OUT}/fonts.json "${J}")
