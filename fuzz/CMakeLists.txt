#
# libwebsockets - fuzz targets for untrusted-input parsers
#
# Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# Each fuzz target lives in fuzz-<name>/ with the harness in main.c and
# committed starting inputs in fuzz-<name>/seeds/.  ctest runs each target
# against its seeds only, as a fast smoke test of the harness under ASan; use
# ./fuzz/run.sh for actual fuzzing campaigns with persistent corpora.
#

if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
	message(FATAL_ERROR "LWS_WITH_FUZZERS needs clang for libFuzzer support (found '${CMAKE_C_COMPILER_ID}').  Install clang and libclang-rt-*-dev and set CC=clang.")
endif()

#
# Inputs:	<name>		 target name, fuzz-<name>/main.c etc
#
macro(lws_add_fuzz_target name)

	add_executable(fuzz-${name} fuzz-${name}/main.c)
	target_compile_options(fuzz-${name} PRIVATE -fsanitize=fuzzer,address)
	target_link_options(fuzz-${name} PRIVATE -fsanitize=fuzzer,address)
	target_link_libraries(fuzz-${name} websockets ${LIBWEBSOCKETS_DEP_LIBS})

	# run the harness once over each seed under ASan, deterministically

	add_test(NAME fuzz-${name}-smoke
		 COMMAND fuzz-${name}
			 ${CMAKE_CURRENT_SOURCE_DIR}/fuzz-${name}/seeds
			 -runs=0)
	set_tests_properties(fuzz-${name}-smoke PROPERTIES TIMEOUT 300)

endmacro()

if (LWS_WITH_LEJP)
	lws_add_fuzz_target(lejp)
endif()

if (LWS_WITH_CBOR)
	lws_add_fuzz_target(lecp)
endif()

if (LWS_WITH_HTTP3 AND LWS_WITH_NETWORK)
	lws_add_fuzz_target(qpack)
endif()

if (LWS_WITH_UPNG AND LWS_WITH_GZINFLATE)
	lws_add_fuzz_target(upng)
endif()

if (LWS_WITH_LHP AND LWS_WITH_DLO)
	lws_add_fuzz_target(lhp)
endif()

# the wsi-bound protocol parsers need the evil-peer helper in peer.h, which
# uses socketpair + adopt, so they are POSIX-only

if (UNIX AND LWS_WITH_NETWORK)
	lws_add_fuzz_target(h1)

	if (LWS_WITH_HTTP2)
		lws_add_fuzz_target(h2)
	endif()

	if (LWS_ROLE_WS)
		lws_add_fuzz_target(ws)
	endif()
endif()
