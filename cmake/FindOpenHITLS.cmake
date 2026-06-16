# Find OpenHITLS library and headers
#
# Sets:
#  OPENHITLS_FOUND
#  OPENHITLS_LIBRARIES
#  OPENHITLS_INCLUDE_DIRS

set(OPENHITLS_ROOT "" CACHE PATH "Prefix for OpenHITLS installation")
set(OPENHITLS_UNSUPPORTED_PLATFORM 0)

if (WIN32 OR CMAKE_SYSTEM_NAME MATCHES "Emscripten|WASI|Generic")
	set(OPENHITLS_UNSUPPORTED_PLATFORM 1)
endif()

if (NOT OPENHITLS_UNSUPPORTED_PLATFORM)
	if ("${OPENHITLS_LIBRARIES}" STREQUAL "" OR "${OPENHITLS_INCLUDE_DIRS}" STREQUAL "")
		include(FindPkgConfig)
		PKG_SEARCH_MODULE(OPENHITLS openhitls)
	endif()

	set(_OPENHITLS_HINTS)
	if (OPENHITLS_ROOT)
		list(APPEND _OPENHITLS_HINTS ${OPENHITLS_ROOT})
	endif()
	list(APPEND _OPENHITLS_HINTS /usr/local /usr)

	# Find the base include directory containing hitls/
	# Only search if pkg-config didn't provide include dirs
	if ("${OPENHITLS_INCLUDE_DIRS}" STREQUAL "")
		find_path(_OPENHITLS_BASE_INCLUDE_DIR hitls/tls/hitls.h
			PATHS ${_OPENHITLS_HINTS}
			PATH_SUFFIXES include)

		if (_OPENHITLS_BASE_INCLUDE_DIR)
			# Base include dir (for #include <hitls/tls/hitls.h>)
			list(APPEND OPENHITLS_INCLUDE_DIRS ${_OPENHITLS_BASE_INCLUDE_DIR})
		endif()
	endif()

	# Build include directories list from base include dirs, including
	# pkg-config-provided base include paths.
	set(_OPENHITLS_BASE_INCLUDE_CANDIDATES)
	foreach(_openhitls_inc ${OPENHITLS_INCLUDE_DIRS})
		if (EXISTS "${_openhitls_inc}/hitls/tls/hitls.h")
			list(APPEND _OPENHITLS_BASE_INCLUDE_CANDIDATES "${_openhitls_inc}")
		endif()
	endforeach()

	foreach(_openhitls_base ${_OPENHITLS_BASE_INCLUDE_CANDIDATES})
		# Subdirectory includes (for #include "crypt_types.h", etc.)
		list(APPEND OPENHITLS_INCLUDE_DIRS "${_openhitls_base}/hitls/bsl")
		list(APPEND OPENHITLS_INCLUDE_DIRS "${_openhitls_base}/hitls/crypto")
		list(APPEND OPENHITLS_INCLUDE_DIRS "${_openhitls_base}/hitls/pki")
		list(APPEND OPENHITLS_INCLUDE_DIRS "${_openhitls_base}/hitls/tls")
		list(APPEND OPENHITLS_INCLUDE_DIRS "${_openhitls_base}/hitls/auth")
	endforeach()
	if (OPENHITLS_INCLUDE_DIRS)
		list(REMOVE_DUPLICATES OPENHITLS_INCLUDE_DIRS)
	endif()

	if ("${OPENHITLS_LIBRARIES}" STREQUAL "")
		find_library(OPENHITLS_BSL_LIBRARY hitls_bsl
			PATHS ${_OPENHITLS_HINTS}
			PATH_SUFFIXES lib)
		find_library(OPENHITLS_CRYPTO_LIBRARY hitls_crypto
			PATHS ${_OPENHITLS_HINTS}
			PATH_SUFFIXES lib)
		find_library(OPENHITLS_TLS_LIBRARY hitls_tls
			PATHS ${_OPENHITLS_HINTS}
			PATH_SUFFIXES lib)
		find_library(OPENHITLS_PKI_LIBRARY hitls_pki
			PATHS ${_OPENHITLS_HINTS}
			PATH_SUFFIXES lib)
		if (OPENHITLS_BSL_LIBRARY AND OPENHITLS_CRYPTO_LIBRARY AND OPENHITLS_TLS_LIBRARY AND OPENHITLS_PKI_LIBRARY)
			set(OPENHITLS_LIBRARIES
				${OPENHITLS_BSL_LIBRARY}
				${OPENHITLS_CRYPTO_LIBRARY}
				${OPENHITLS_TLS_LIBRARY}
				${OPENHITLS_PKI_LIBRARY})
		endif()
	endif()
endif()

if (OPENHITLS_UNSUPPORTED_PLATFORM)
	set(OPENHITLS_FOUND 0)
elseif ("${OPENHITLS_LIBRARIES}" STREQUAL "" OR "${OPENHITLS_INCLUDE_DIRS}" STREQUAL "")
	set(OPENHITLS_FOUND 0)
else()
	set(OPENHITLS_FOUND 1)
endif()
