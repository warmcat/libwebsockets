project(lws-api-test-lhp-dlo C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-lhp-dlo)
set(SRCS main.c )

set(requirements 1)
require_lws_config(LWS_WITH_UPNG 1 requirements)
require_lws_config(LWS_WITH_LHP 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
# lhp fetches its assets through a secure stream from the JSON policy
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# Layout regression tests: each cases/NN-name.html is laid out and the
	# DLO tree dump compared with cases/NN-name.dlo (see lhp-dlo-case.cmake)
	#

		if (LWS_WITH_FILE_OPS AND NOT WIN32)
			file(GLOB LHP_CASES ${CMAKE_CURRENT_SOURCE_DIR}/cases/*.html)
			# 11-asset-queue gets its own entry below, with a small fd limit
			# 13-adblock gets its own entry below, with the ad filter files
			# 14-asset-cache gets its own entry below, with the asset cache
			# 21-image-reclaim is a render comparison below
			# 34-tag-case-upper is compared with 34-tag-case's golden
			# 35-tiny-viewport gets its own entry below, at panel size
			# 37- and 38-boot-overlay get their own entries below,
			# at the display sizes they were made for
			list(REMOVE_ITEM LHP_CASES
					${CMAKE_CURRENT_SOURCE_DIR}/cases/11-asset-queue.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/13-adblock.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/14-asset-cache.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/21-image-reclaim.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/23-abs-image.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/29-bg-cover.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/34-tag-case-upper.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/35-tiny-viewport.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/37-boot-overlay.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/38-boot-overlay-window.html)
		foreach(C ${LHP_CASES})
			get_filename_component(CN ${C} NAME_WE)
			# a case whose assets need a decoder this build lacks
			# lays out differently from its golden: skip it
			file(READ ${C} CASE_HTML)
			string(FIND "${CASE_HTML}" ".svg" HAS_SVG)
			string(FIND "${CASE_HTML}" ".gif" HAS_GIF)
			if (NOT LWS_WITH_SVG AND NOT HAS_SVG EQUAL -1)
				continue()
			endif()
			if (NOT LWS_WITH_GIF AND NOT HAS_GIF EQUAL -1)
				continue()
			endif()
			add_test(NAME api-test-lhp-dlo-${CN}
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${C}
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/${CN}.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/${CN}.dlo
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endforeach()

		# six images on a context with a tiny fd table: the fetches must
		# queue behind each other and still all arrive (svg images)
		if (LWS_WITH_SVG)
		add_test(NAME api-test-lhp-dlo-11-asset-queue
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/11-asset-queue.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/11-asset-queue.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/11-asset-queue.dlo
				-DFLAGS=--fd-limit=6
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endif()

		# the ad-block case: with the cosmetic filter css and the url block
		# list applied, the junk elements and their fixed-height boxes are
		# gone from the layout and the blocked assets are never fetched
		# (svg images)
		if (LWS_WITH_SVG)
		add_test(NAME api-test-lhp-dlo-13-adblock
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/13-adblock.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/13-adblock.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/13-adblock.dlo
				-DCSS_FILTER=${CMAKE_CURRENT_SOURCE_DIR}/cases/13-adblock.css
				-DBLOCK_LIST=${CMAKE_CURRENT_SOURCE_DIR}/cases/13-adblock.list
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endif()

		# html tag and attribute names ignore case: the same page in
		# upper and mixed case, including the body and abs / fixed boxes
		# with no positioned ancestor (which crashed the layout when
		# <BODY> got no body rect, G-667), an <IMG SRC> and a
		# <LINK REL=StyleSheet>, must lay out as the lower case one
		# (svg image)
		if (LWS_WITH_SVG)
		add_test(NAME api-test-lhp-dlo-34-tag-case-upper
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/34-tag-case-upper.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/34-tag-case.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/34-tag-case-upper.dlo
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endif()

		# the user-agent body and heading margins are capped against
		# the surface: on a 104 x 212 epd the page starts 4px in and the
		# h1's top margin is 10px, not the browser's 8px and 21px
		add_test(NAME api-test-lhp-dlo-35-tiny-viewport
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/35-tiny-viewport.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/35-tiny-viewport.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/35-tiny-viewport.dlo
				-DW=104 -DH=212
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)

		# the boot overlay of the lhp embedded examples, as boot-ui.c
		# made it before it was a strip ui (lws-dlo-ui.h, see
		# api-test-dlo-ui): a table of a row per boot stage, its icon and what
		# we know about it.  On a 600 x 448 epd the whole table fits;
		# on a 128 x 64 oled it's shown through a window, offset so the
		# row being worked on is in its middle
		if (LWS_WITH_SVG)
			add_test(NAME api-test-lhp-dlo-37-boot-overlay
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/37-boot-overlay.html
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/37-boot-overlay.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/37-boot-overlay.dlo
					-DW=600 -DH=448
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
			add_test(NAME api-test-lhp-dlo-38-boot-overlay-window
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/38-boot-overlay-window.html
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/38-boot-overlay-window.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/38-boot-overlay-window.dlo
					-DW=128 -DH=64
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endif()

		if (LWS_WITH_CACHE_BLOB)
			# with the asset cache enabled and bluecat.jpg preseeded
			# into it under an unreachable url, the layout shows the
			# image with its real dimensions from the cache with no
			# network; the second image is not in the cache and is a
			# local path that does not exist, so it fails the same way
			# on every platform without touching dns or tls
			add_test(NAME api-test-lhp-dlo-14-asset-cache
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/14-asset-cache.html
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/14-asset-cache.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/14-asset-cache.dlo
					-DASSET_CACHE_DIR=${CMAKE_CURRENT_BINARY_DIR}/14-asset-cache-scratch
					-DPRESEED=https://missing.invalid/bluecat.jpg=${CMAKE_CURRENT_SOURCE_DIR}/bluecat.jpg
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)

			# the aspect-ratio box idiom (absolutely positioned image
			# filling a padding-top: 56.25% picture), escaped
			# tailwind class selectors, and abs offsets from the
			# padding box; the image comes from the (preseeded) cache
			add_test(NAME api-test-lhp-dlo-23-abs-image
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/23-abs-image.html
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/23-abs-image.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/23-abs-image.dlo
					-DASSET_CACHE_DIR=${CMAKE_CURRENT_BINARY_DIR}/23-abs-image-scratch
					-DPRESEED=https://missing.invalid/exclaim.png=${CMAKE_CURRENT_SOURCE_DIR}/exclaim.png
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)

			# background shorthand url() term + background-size:
			# cover sized to the element box at close; the image
			# comes from the (preseeded) cache
			add_test(NAME api-test-lhp-dlo-29-bg-cover
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/29-bg-cover.html
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/29-bg-cover.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/29-bg-cover.dlo
					-DASSET_CACHE_DIR=${CMAKE_CURRENT_BINARY_DIR}/29-bg-cover-scratch
					-DPRESEED=https://missing.invalid/bluecat.jpg=${CMAKE_CURRENT_SOURCE_DIR}/bluecat.jpg
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endif()

		add_test(NAME api-test-lhp-dlo-test-html
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/test.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/test.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/test.dlo
				-DW=600 -DH=448
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)

		# the same page with the faces coming from the .mcufont files
		# in the repository instead of the built-in blobs, under a
		# heap limit tight enough that their dictionaries and glyphs
		# are evicted and reloaded many times during the layout: the
		# result must be the same
		add_test(NAME api-test-lhp-dlo-test-html-file-fonts-reclaim
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/test.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/test.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/test-file-fonts.dlo
				-DW=600 -DH=448
				"-DFLAGS=--fonts;${CMAKE_CURRENT_SOURCE_DIR}/../../../contrib/mcufont/fonts;--heap-limit;90000"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)

		# glyph pairs are kerned by the shapes of their ink, the same
		# way for measuring and laying out; for the built-in face, and
		# for the same face from its file alone, under a heap limit so
		# tight that its glyphs are evicted again and again while the
		# pairs are compared
		add_test(NAME api-test-lhp-dlo-kern
			 COMMAND ${SAMP} --kern-check)
		add_test(NAME api-test-lhp-dlo-kern-face-setup
			 COMMAND ${CMAKE_COMMAND} -E copy
				${CMAKE_CURRENT_SOURCE_DIR}/../../../contrib/mcufont/fonts/FiraSansCondensed-Regular14.mcufont
				${CMAKE_CURRENT_BINARY_DIR}/kern-face/FiraSansCondensed-Regular14.mcufont)
		set_tests_properties(api-test-lhp-dlo-kern-face-setup PROPERTIES
				     FIXTURES_SETUP lhp_kern_face)
		add_test(NAME api-test-lhp-dlo-kern-file-font-reclaim
			 COMMAND ${SAMP} --kern-check
				--fonts ${CMAKE_CURRENT_BINARY_DIR}/kern-face
				--heap-limit 4000)
		set_tests_properties(api-test-lhp-dlo-kern-file-font-reclaim
				     PROPERTIES FIXTURES_REQUIRED lhp_kern_face)
		set_tests_properties(api-test-lhp-dlo-kern
				     api-test-lhp-dlo-kern-file-font-reclaim
				     PROPERTIES TIMEOUT 60)

		# fonts as a system attribute: one face built in, the rest
		# listed by a manifest and fetched as text needs them.  The
		# fixture lays out a directory as a server would serve it
		set(RF ${CMAKE_CURRENT_BINARY_DIR}/remote-fonts)
		add_test(NAME api-test-lhp-dlo-remote-fonts-setup
			 COMMAND ${CMAKE_COMMAND}
				-DFONTS=${CMAKE_CURRENT_SOURCE_DIR}/../../../contrib/mcufont/fonts
				-DMANIFEST_TOOL=${CMAKE_CURRENT_SOURCE_DIR}/../../../contrib/mcufont/fonts-manifest.cmake
				-DOUT=${RF}
				-P ${CMAKE_CURRENT_SOURCE_DIR}/remote-fonts-setup.cmake)
		set_tests_properties(api-test-lhp-dlo-remote-fonts-setup
				     PROPERTIES FIXTURES_SETUP lhp_remote_fonts)

		# the faces from the manifest, with every reclaimable occupant
		# evicted as every element opens, so they are fetched
		# again and again during the layout: the same layout as the
		# built-in faces give.  (A heap limit did this before, but
		# where it bites depends on the allocator and the build: with
		# nothing left to reclaim, the layout itself ran out of memory
		# on some platforms)
		add_test(NAME api-test-lhp-dlo-test-html-remote-fonts-reclaim
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/test.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/test.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/test-remote-fonts.dlo
				-DW=600 -DH=448
				"-DFLAGS=--font-manifest;file://${RF}/faces/fonts.json;--reclaim-elems;1"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)

		# ... and rendered with every face evicted every few lines, so
		# they are fetched again and again during the render: the same
		# pixels as the built-in faces give
		add_test(NAME api-test-lhp-dlo-render-remote-fonts-reclaim
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/test.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/test-remote-fonts
				-DW=600 -DH=448
				"-DFLAGS_B=--font-manifest;file://${RF}/faces/fonts.json;--reclaim-lines;7"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		# ... and with the heap all in use for a while once they have
		# been evicted, so at first they can't be fetched again: the
		# render waits for them, rather than drawing the text in
		# another face than the one it was laid out in, and comes out
		# as it does with them resident.  (The heap is only refused
		# where an allocation can be sized: elsewhere this comes out
		# the same as the plain render without proving anything)
		add_test(NAME api-test-lhp-dlo-render-remote-fonts-starved
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/36-font-pages.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/36-font-pages-starved
				"-DCOMMON=--font-manifest;file://${RF}/faces/fonts.json"
				"-DFLAGS_B=--reclaim-lines;7;--starve-ms;500"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		# ... and for longer than the render waits for them: the page
		# is laid out again keeping the faces it uses resident, once
		# the heap is back, so however often the render evicts, it
		# comes out as it does with them resident from the start.
		# Only where the heap can be refused: elsewhere the faces are
		# fetched again and it's laid out only once, which proves
		# nothing
		if (LWS_HAVE_MALLOC_USABLE_SIZE)
			add_test(NAME api-test-lhp-dlo-render-remote-fonts-starved-long
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/36-font-pages.html
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/36-font-pages-starved-long
					"-DCOMMON=--font-manifest;file://${RF}/faces/fonts.json"
					"-DFLAGS_B=--reclaim-lines;7;--starve-ms;5000"
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)
			set_tests_properties(api-test-lhp-dlo-render-remote-fonts-starved-long
					     PROPERTIES FIXTURES_REQUIRED lhp_remote_fonts)
		endif()

		# without the manifest, or with a manifest whose faces can't
		# be fetched, the page is shown in the built-in face, and
		# comes out the same either way
		add_test(NAME api-test-lhp-dlo-remote-fonts-fallback
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/test.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/remote-fonts-fallback
				-DW=600 -DH=448
				"-DFLAGS_A=--font-manifest;file://${RF}/missing/fonts.json"
				"-DFLAGS_B=--font-manifest;file://${RF}/nofaces/fonts.json"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		# text with glyphs from a second page of the faces, the
		# dashes on page 0020: the same layout as the built-in faces
		# give, with both pages being evicted and fetched again as
		# every element opens
		add_test(NAME api-test-lhp-dlo-36-font-pages-remote
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/36-font-pages.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/36-font-pages.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/36-font-pages-remote.dlo
				"-DFLAGS=--font-manifest;file://${RF}/faces/fonts.json;--reclaim-elems;1"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		set(LHP_REMOTE_TESTS api-test-lhp-dlo-36-font-pages-remote)

		if (LWS_WITH_SERVER)
			# from an http server that refuses page 0020 with a
			# 404, as one still making it would: just the runs
			# with dashes in are set in the built-in face, and the
			# rest still in the faces from the server
			add_test(NAME api-test-lhp-dlo-36-font-pages-refused
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/36-font-pages.html
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/36-font-pages-refused.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/36-font-pages-refused.dlo
					"-DFLAGS=--serve-fonts;${RF}/nopunct"
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
			list(APPEND LHP_REMOTE_TESTS
			     api-test-lhp-dlo-36-font-pages-refused)
		endif()

		set_tests_properties(api-test-lhp-dlo-test-html-remote-fonts-reclaim
				     api-test-lhp-dlo-render-remote-fonts-reclaim
				     api-test-lhp-dlo-render-remote-fonts-starved
				     api-test-lhp-dlo-remote-fonts-fallback
				     ${LHP_REMOTE_TESTS}
				     PROPERTIES FIXTURES_REQUIRED lhp_remote_fonts)

		# a page with a (preseeded) cached image, rendered with the
		# faces from files while every reclaimable occupant (the font
		# tables and glyphs, the image's payload and decoder) is
		# evicted every few lines and has to renew itself mid-render,
		# against the same render left alone: the pixels must be
		# identical.  (A heap limit did this before, but where the
		# limit bites depends on the allocator: it evicted the image
		# under glibc and nothing decodable under ASan)
		add_test(NAME api-test-lhp-dlo-render-reclaim
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/21-image-reclaim.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/21-image-reclaim
				-DW=600 -DH=448
				"-DCOMMON=--preseed;https://missing.invalid/exclaim.png=${CMAKE_CURRENT_SOURCE_DIR}/exclaim.png"
				"-DFLAGS_B=--fonts;${CMAKE_CURRENT_SOURCE_DIR}/../../../contrib/mcufont/fonts;--reclaim-lines;7"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		# interlaced gifs come out exactly as the same pixels gif'd
		# progressively: each row once, in the right place, from one
		# decode however the sweep asks for rows (G-462)
		if (LWS_WITH_GIF)
		add_test(NAME api-test-lhp-dlo-gif-interlaced-render
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/gif-interlaced.html
				-DHTML_B=${CMAKE_CURRENT_SOURCE_DIR}/gif-interlaced-twin.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/gif-interlaced
				-DW=100 -DH=80
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)
		endif()

		# a vertical list of local svg icons the css gives a size to
		# holds one at a time: each is only fetched when the raster
		# reaches it and given back when the raster leaves it.  It
		# comes out as the same icons without a size, which are fetched
		# for the layout, given back when it completes, and fetched
		# again for the render
		if (LWS_WITH_SVG)
		add_test(NAME api-test-lhp-dlo-svg-stack-render
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/svg-stack.html
				-DHTML_B=${CMAKE_CURRENT_SOURCE_DIR}/svg-stack-twin.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/svg-stack
				-DW=100 -DH=240
				"-DFLAGS_A=--svg-live-max;1"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		# ... and the same when the display list is retained (eg, for
		# a touch panel), where the icons' dlos stay after the raster
		# has passed them, but what they held is given back
		add_test(NAME api-test-lhp-dlo-svg-stack-retained
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/svg-stack.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/svg-stack-retained
				-DW=100 -DH=240
				"-DFLAGS_A=--retained;--svg-live-max;1"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)
		endif()

		# a retained page changed in place, an element's text and
		# another's width, with its animated svg moved on, comes out
		# as the page laid out with them like that would, when only
		# the lines lws_display_render_damage() gives are drawn again:
		# those of the svg and of the bar the changes are in
		if (LWS_WITH_SVG)
		add_test(NAME api-test-lhp-dlo-in-place-render
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/in-place.html
				-DHTML_B=${CMAKE_CURRENT_SOURCE_DIR}/in-place-twin.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/in-place
				-DW=200 -DH=160
				"-DFLAGS_A=--retained;--anim-t;100;--change;pd=45%,pf=45%,f:w=72,t=700;--expect-damage;32,124"
				"-DFLAGS_B=--anim-t;700"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)
		endif()

		# ... and a page with nothing animated, drawn again later with
		# nothing changed, has nothing to draw again
		add_test(NAME api-test-lhp-dlo-in-place-none
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/rounded-clip.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/in-place-none
				-DW=240 -DH=210
				"-DFLAGS_A=--retained;--change;t=500;--expect-damage;none"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		# a list moved up inside an overflow: hidden window shows just
		# what is in the window, as the same rows laid out there would,
		# including text laid out below the surface before the move
		add_test(NAME api-test-lhp-dlo-overflow-clip-render
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/overflow-clip.html
				-DHTML_B=${CMAKE_CURRENT_SOURCE_DIR}/overflow-clip-twin.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/overflow-clip
				-DW=100 -DH=40
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		# overflow: hidden on a box with rounded corners clips what is in
		# it to them, covering each pixel as much as the box would be
		# drawn itself: a box filled by a child, or with a sliver of one
		# at either end, comes out the same as the box drawn that colour,
		# or a box rounded only at that end
		add_test(NAME api-test-lhp-dlo-rounded-clip-render
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/rounded-clip.html
				-DHTML_B=${CMAKE_CURRENT_SOURCE_DIR}/rounded-clip-twin.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/rounded-clip
				-DW=240 -DH=210
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		# borders are laid out and drawn, per side, and collapsed in a
		# table, as plain boxes drawing the same pixels are
		add_test(NAME api-test-lhp-dlo-border-render
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/border.html
				-DHTML_B=${CMAKE_CURRENT_SOURCE_DIR}/border-twin.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/border
				-DW=172 -DH=100
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		# a retained display list scanned again panned down skips the
		# subtrees with nothing on each line, but still finds what is
		# positioned outside its parent's box, overflowing a zero height
		# box, or cut by the top of the view, and comes out as the same
		# view rendered streaming, which visits everything
		if (LWS_WITH_JPEG)
		add_test(NAME api-test-lhp-dlo-pan-extents-render
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/pan-extents.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/pan-extents
				-DW=120 -DH=100
				"-DCOMMON=--layout-h;600"
				"-DFLAGS_A=--retained;--pan;0,0:0,47"
				"-DFLAGS_B=--pan;0,47"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)
		endif()

		# panning a retained display list over more and more of a long
		# page holds no more heap: what the text was drawn with is let
		# go when it can't be seen.  The last view is the same as the
		# view rendered streaming.  The page has no assets, and a file
		# cache's background scan would hold heap of its own during
		# the pans on a slow builder, so it renders with no cache
		add_test(NAME api-test-lhp-dlo-pan-heap
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/pan-heap.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/pan-heap
				-DW=120 -DH=100
				-DNO_ASSET_CACHE=1
				"-DCOMMON=--layout-h;4000"
				"-DFLAGS_A=--retained;--pan;0,0:0,300:0,600:0,900:0,1200:0,1500:0,1800:0,2100;--pan-heap-max;8192"
				"-DFLAGS_B=--pan;0,2100"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		if (LWS_WITH_DLO_ASSET_CACHE)
			# an in-memory only asset cache, as on a device with no
			# filesystem, sized as a device can spare: the cached
			# image is laid out with its real dimensions, the same
			# as from the file-backed cache
			add_test(NAME api-test-lhp-dlo-14-asset-cache-heap
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/14-asset-cache.html
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/14-asset-cache.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/14-asset-cache-heap.dlo
					-DASSET_CACHE_HEAP=131072
					-DPRESEED=https://missing.invalid/bluecat.jpg=${CMAKE_CURRENT_SOURCE_DIR}/bluecat.jpg
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)

			# panning a retained display list draws an image again
			# at each pan, after the raster let it go: it must come
			# back from the in-memory cache, since where it came from
			# can't be reached, and the last view is the same as the
			# view rendered streaming
			add_test(NAME api-test-lhp-dlo-pan-cache-heap
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/pan-cache.html
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/pan-cache-heap
					-DW=120 -DH=60
					-DASSET_CACHE_HEAP=131072
					"-DCOMMON=--layout-h;400;--preseed;https://missing.invalid/exclaim.png=${CMAKE_CURRENT_SOURCE_DIR}/exclaim.png"
					"-DFLAGS_A=--retained;--pan;0,0:0,10:0,20:0,25"
					"-DFLAGS_B=--pan;0,25"
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)
		endif()

		# css opacity on a block reaches the pixels of everything inside
		# it: the same as the opacity given to each of its children
		if (LWS_WITH_SVG)
		add_test(NAME api-test-lhp-dlo-opacity-render
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/opacity-group.html
				-DHTML_B=${CMAKE_CURRENT_SOURCE_DIR}/opacity-group-twin.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/opacity-group
				-DW=100 -DH=40
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)
		endif()

		# captured real-world pages, with their network assets made
		# unreachable so the layout is the same every run; lobsters'
		# golden includes its svg asset, slashdot's its svg and gif ones
		set(LHP_VECTORS)
		if (LWS_WITH_SVG)
			list(APPEND LHP_VECTORS lobsters-1/lobsters)
		endif()
		if (LWS_WITH_SVG AND LWS_WITH_GIF)
			list(APPEND LHP_VECTORS slashdot-1/slashdot-1)
		endif()
		foreach(VEC ${LHP_VECTORS})
			get_filename_component(VN ${VEC} NAME)
			add_test(NAME api-test-lhp-dlo-vector-${VN}
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/vectors/${VEC}.html
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/vectors/${VEC}.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/${VN}.dlo
					-DW=800 -DH=1200 -DLOCALIZE=1
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endforeach()

		# the captured slashdot page again, with an ad / tracker filter
		# applied: the banner leaderboard below the menu header and the
		# rail ads are removed from the layout by the filter css, and the
		# blocked ad hosts are never fetched
		if (LWS_WITH_SVG AND LWS_WITH_GIF)
		add_test(NAME api-test-lhp-dlo-vector-slashdot-1-adblock
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/vectors/slashdot-1/slashdot-1.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/vectors/slashdot-1/slashdot-1-adblock.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/slashdot-1-adblock.dlo
				-DW=800 -DH=1200 -DLOCALIZE=1
				-DCSS_FILTER=${CMAKE_CURRENT_SOURCE_DIR}/vectors/slashdot-1/filter.css
				-DBLOCK_LIST=${CMAKE_CURRENT_SOURCE_DIR}/vectors/slashdot-1/filter.list
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endif()
	endif()
endif()
