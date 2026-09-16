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
			list(REMOVE_ITEM LHP_CASES
					${CMAKE_CURRENT_SOURCE_DIR}/cases/11-asset-queue.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/13-adblock.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/14-asset-cache.html
					${CMAKE_CURRENT_SOURCE_DIR}/cases/21-image-reclaim.html)
		foreach(C ${LHP_CASES})
			get_filename_component(CN ${C} NAME_WE)
			add_test(NAME api-test-lhp-dlo-${CN}
				 COMMAND ${CMAKE_COMMAND}
					-DTOOL=$<TARGET_FILE:${SAMP}>
					-DHTML=${C}
					-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/${CN}.dlo
					-DOUT=${CMAKE_CURRENT_BINARY_DIR}/${CN}.dlo
					-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)
		endforeach()

		# six images on a context with a tiny fd table: the fetches must
		# queue behind each other and still all arrive
		add_test(NAME api-test-lhp-dlo-11-asset-queue
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/11-asset-queue.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/11-asset-queue.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/11-asset-queue.dlo
				-DFLAGS=--fd-limit=6
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)

		# the ad-block case: with the cosmetic filter css and the url block
		# list applied, the junk elements and their fixed-height boxes are
		# gone from the layout and the blocked assets are never fetched
		add_test(NAME api-test-lhp-dlo-13-adblock
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/13-adblock.html
				-DGOLDEN=${CMAKE_CURRENT_SOURCE_DIR}/cases/13-adblock.dlo
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/13-adblock.dlo
				-DCSS_FILTER=${CMAKE_CURRENT_SOURCE_DIR}/cases/13-adblock.css
				-DBLOCK_LIST=${CMAKE_CURRENT_SOURCE_DIR}/cases/13-adblock.list
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-dlo-case.cmake)

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

		# a page with a (preseeded) cached image, rendered with the
		# faces from files under a heap limit that evicts the fonts
		# and the image's payload and decoder during the layout and
		# render, against the same render with no limit: the pixels
		# must be identical
		add_test(NAME api-test-lhp-dlo-render-reclaim
			 COMMAND ${CMAKE_COMMAND}
				-DTOOL=$<TARGET_FILE:${SAMP}>
				-DHTML=${CMAKE_CURRENT_SOURCE_DIR}/cases/21-image-reclaim.html
				-DOUT=${CMAKE_CURRENT_BINARY_DIR}/21-image-reclaim
				-DW=600 -DH=448
				"-DCOMMON=--preseed;https://missing.invalid/exclaim.png=${CMAKE_CURRENT_SOURCE_DIR}/exclaim.png"
				"-DFLAGS_B=--fonts;${CMAKE_CURRENT_SOURCE_DIR}/../../../contrib/mcufont/fonts;--heap-limit;50000"
				-P ${CMAKE_CURRENT_SOURCE_DIR}/lhp-render-compare.cmake)

		# captured real-world pages, with their network assets made
		# unreachable so the layout is the same every run
		foreach(VEC lobsters-1/lobsters slashdot-1/slashdot-1)
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
