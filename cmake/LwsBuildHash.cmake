#
# Run in cmake script mode (-P) by the lws_build_hash target, on every make.
#
# lws_config.h takes LWS_BUILD_HASH from git when cmake configures, and a
# build dir that follows git for a long time without reconfiguring goes on
# reporting that old hash.  This reruns git describe at make time and writes
# the hash and version the library reports into a private header, touching it
# only when they changed so a no-op make rebuilds nothing.
#
# LWS_BUILD_HASH in lws_config.h stays the configure-time one, since plugins
# built out of tree are matched against the library with it.
#
#  -DLWS_SRC_DIR=      the lws checkout
#  -DLWS_GIT=          git executable, or empty
#  -DLWS_HASH_PREFIX=  "user@host-" for a non-reproducible build, or empty
#  -DLWS_HASH_FALLBACK= configure-time LWS_BUILD_HASH, used if git fails
#  -DLWS_VERSION_BASE= eg, "5.1.99"
#  -DOUT=              the header to write
#

set(HASH "${LWS_HASH_FALLBACK}")

if (LWS_GIT)
	execute_process(
		COMMAND "${LWS_GIT}" describe --tags --always
		WORKING_DIRECTORY "${LWS_SRC_DIR}"
		RESULT_VARIABLE GIT_RESULT
		OUTPUT_VARIABLE GIT_OUT
		OUTPUT_STRIP_TRAILING_WHITESPACE
		ERROR_QUIET)
	if (GIT_RESULT EQUAL 0 AND NOT "${GIT_OUT}" STREQUAL "")
		set(HASH "${LWS_HASH_PREFIX}${GIT_OUT}")
	endif()
endif()

set(NEW "/* generated at make time by cmake/LwsBuildHash.cmake */\n\n#define LWS_BUILT_HASH \"${HASH}\"\n#define LWS_BUILT_VERSION \"${LWS_VERSION_BASE}-${HASH}\"\n")

set(OLD "")
if (EXISTS "${OUT}")
	file(READ "${OUT}" OLD)
endif()
if (NOT "${OLD}" STREQUAL "${NEW}")
	file(WRITE "${OUT}" "${NEW}")
endif()
