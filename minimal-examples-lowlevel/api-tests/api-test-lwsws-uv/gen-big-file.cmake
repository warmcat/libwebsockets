#
# Generates the deterministic multi-MB file the api-test-lwsws-uv file mount
# serves, so no binary blob has to live in git.
#
# cmake -DOUT=<path> -DSIZE_MB=<n> -P gen-big-file.cmake
#
# The content is the 16-byte unit below repeated, so the test can verify any
# byte it receives at offset n against unit[n % 16] without knowing a digest.
#

set(unit "0123456789abcdef")

set(k1 "")
foreach(i RANGE 1 64)
	set(k1 "${k1}${unit}")
endforeach()			# 1KB

set(k64 "")
foreach(i RANGE 1 64)
	set(k64 "${k64}${k1}")
endforeach()			# 64KB

file(WRITE "${OUT}" "")

math(EXPR reps "${SIZE_MB} * 16")
foreach(i RANGE 1 ${reps})
	file(APPEND "${OUT}" "${k64}")
endforeach()
