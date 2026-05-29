#
# libwebsockets - small server side websockets and web server implementation
#
# Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
# The strategy is to only export to PARENT_SCOPE
#
#  - changes to LIB_LIST
#  - changes to SOURCES
#  - includes via include_directories
#
# and keep everything else private

include_directories(wrapper/include wrapper/include/internal)

 	set(LWS_WITH_SSL ON)
 	
	include_directories(wrapper/include)
	include_directories(wrapper/include/platform)
	include_directories(wrapper/include/internal)
	include_directories(wrapper/include/openssl)
 	
 	if (LWS_WITH_NETWORK)
		list(APPEND HDR_PRIVATE
			tls/mbedtls/wrapper/include/internal/ssl3.h
			tls/mbedtls/wrapper/include/internal/ssl_cert.h
			tls/mbedtls/wrapper/include/internal/ssl_code.h
			tls/mbedtls/wrapper/include/internal/ssl_dbg.h
			tls/mbedtls/wrapper/include/internal/ssl_lib.h
			tls/mbedtls/wrapper/include/internal/ssl_methods.h
			tls/mbedtls/wrapper/include/internal/ssl_pkey.h
			tls/mbedtls/wrapper/include/internal/ssl_stack.h
			tls/mbedtls/wrapper/include/internal/ssl_types.h
			tls/mbedtls/wrapper/include/internal/ssl_x509.h
			tls/mbedtls/wrapper/include/internal/tls1.h
			tls/mbedtls/wrapper/include/internal/x509_vfy.h)
	
		list(APPEND HDR_PRIVATE
			tls/mbedtls/wrapper/include/openssl/ssl.h)
	
		list(APPEND HDR_PRIVATE
			tls/mbedtls/wrapper/include/platform/ssl_pm.h
			tls/mbedtls/wrapper/include/platform/ssl_port.h)
	
		list(APPEND SOURCES
			tls/mbedtls/wrapper/library/ssl_cert.c
			tls/mbedtls/wrapper/library/ssl_lib.c
			tls/mbedtls/wrapper/library/ssl_methods.c
			tls/mbedtls/wrapper/library/ssl_pkey.c
			tls/mbedtls/wrapper/library/ssl_stack.c
			tls/mbedtls/wrapper/library/ssl_x509.c)
	
		list(APPEND SOURCES
			tls/mbedtls/wrapper/platform/ssl_pm.c
			tls/mbedtls/wrapper/platform/ssl_port.c)
	endif()

	set(_WANT_MBT 0)
	if (NOT LWS_PLAT_FREERTOS)
		if (NOT DEFINED LWS_MBEDTLS_LIBRARIES)
			set(_WANT_MBT 1)
		endif()
		if (NOT DEFINED LWS_MBEDTLS_INCLUDE_DIRS)
			set(_WANT_MBT 1)
		endif()
	endif()

	if (_WANT_MBT)

		find_path(LWS_MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)

		find_library(MBEDTLS_LIBRARY mbedtls)
		find_library(MBEDX509_LIBRARY mbedx509)
		find_library(MBEDCRYPTO_LIBRARY mbedcrypto)

		set(LWS_MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}" "${MBEDCRYPTO_LIBRARY}")

		include(FindPackageHandleStandardArgs)
		find_package_handle_standard_args(MBEDTLS DEFAULT_MSG
			LWS_MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)

		mark_as_advanced(LWS_MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)

		if ("${LWS_MBEDTLS_LIBRARIES}" STREQUAL "" OR "${LWS_MBEDTLS_INCLUDE_DIRS}" STREQUAL "")
			message(FATAL_ERROR "You must set LWS_MBEDTLS_LIBRARIES and LWS_MBEDTLS_INCLUDE_DIRS when LWS_WITH_MBEDTLS is turned on.")
		endif()
	endif()
	if (LWS_MBEDTLS_LIBRARIES)
		set(MBEDTLS_LIBRARIES ${LWS_MBEDTLS_LIBRARIES})
		set(MBEDTLS_LIBRARIES ${LWS_MBEDTLS_LIBRARIES} PARENT_SCOPE)
	endif()
	if (LWS_MBEDTLS_INCLUDE_DIRS)
		set(MBEDTLS_INCLUDE_DIRS ${LWS_MBEDTLS_INCLUDE_DIRS})
		set(MBEDTLS_INCLUDE_DIRS ${LWS_MBEDTLS_INCLUDE_DIRS} PARENT_SCOPE)
	endif()
	set(USE_MBEDTLS 1 PARENT_SCOPE)
	if (DEFINED MBEDTLS_INCLUDE_DIRS)
		include_directories(${MBEDTLS_INCLUDE_DIRS})
		set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${MBEDTLS_INCLUDE_DIRS})
	endif()

	if (DEFINED MBEDTLS_LIBRARIES)
		list(APPEND LIB_LIST ${MBEDTLS_LIBRARIES})
	endif()

# old mbedtls has everything in mbedtls/net.h

CHECK_C_SOURCE_COMPILES("#include <mbedtls/net_sockets.h>\nint main(void) { return 0;}\n" LWS_HAVE_MBEDTLS_NET_SOCKETS)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/ssl.h>\nint main(void) { return MBEDTLS_SSL_NEW_SESSION_TICKET;}\n" LWS_HAVE_MBEDTLS_SSL_NEW_SESSION_TICKET)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/version.h>\n#if !defined(MBEDTLS_VERSION_MAJOR) || MBEDTLS_VERSION_MAJOR < 4\n#error not mbedtls 4\n#endif\nint main(void) { return 0;}\n" LWS_HAVE_MBEDTLS_V4)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/rsa.h>\nint main(void) { return (int)sizeof(mbedtls_rsa_context); }\n" LWS_HAVE_MBEDTLS_PRIVATE_RSA_H)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/ecp.h>\nint main(void) { return (int)sizeof(mbedtls_ecp_keypair); }\n" LWS_HAVE_MBEDTLS_PRIVATE_ECP_H)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/ecdsa.h>\nint main(void) { return (int)sizeof(mbedtls_ecdsa_context); }\n" LWS_HAVE_MBEDTLS_PRIVATE_ECDSA_H)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/md5.h>\nint main(void) { return (int)sizeof(mbedtls_md5_context); }\n" LWS_HAVE_MBEDTLS_PRIVATE_MD5_H)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/sha1.h>\nint main(void) { return (int)sizeof(mbedtls_sha1_context); }\n" LWS_HAVE_MBEDTLS_PRIVATE_SHA1_H)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/sha256.h>\nint main(void) { return (int)sizeof(mbedtls_sha256_context); }\n" LWS_HAVE_MBEDTLS_PRIVATE_SHA256_H)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/sha512.h>\nint main(void) { return (int)sizeof(mbedtls_sha512_context); }\n" LWS_HAVE_MBEDTLS_PRIVATE_SHA512_H)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/aes.h>\nint main(void) { return (int)sizeof(mbedtls_aes_context); }\n" LWS_HAVE_MBEDTLS_PRIVATE_AES_H)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/gcm.h>\nint main(void) { return (int)sizeof(mbedtls_gcm_context); }\n" LWS_HAVE_MBEDTLS_PRIVATE_GCM_H)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/cipher.h>\nint main(void) { return (int)sizeof(mbedtls_cipher_context_t); }\n" LWS_HAVE_MBEDTLS_PRIVATE_CIPHER_H)
CHECK_C_SOURCE_COMPILES("#include <mbedtls/private/chachapoly.h>\nint main(void) { return (int)sizeof(mbedtls_chachapoly_context); }\n" LWS_HAVE_MBEDTLS_PRIVATE_CHACHAPOLY_H)

if (LWS_HAVE_MBEDTLS_V4 AND
	(NOT LWS_HAVE_MBEDTLS_PRIVATE_RSA_H OR
	 NOT LWS_HAVE_MBEDTLS_PRIVATE_ECP_H OR
	NOT LWS_HAVE_MBEDTLS_PRIVATE_ECDSA_H OR
	NOT LWS_HAVE_MBEDTLS_PRIVATE_MD5_H OR
	NOT LWS_HAVE_MBEDTLS_PRIVATE_SHA1_H OR
	NOT LWS_HAVE_MBEDTLS_PRIVATE_SHA256_H OR
	NOT LWS_HAVE_MBEDTLS_PRIVATE_SHA512_H OR
	NOT LWS_HAVE_MBEDTLS_PRIVATE_AES_H OR
	NOT LWS_HAVE_MBEDTLS_PRIVATE_GCM_H OR
	NOT LWS_HAVE_MBEDTLS_PRIVATE_CIPHER_H OR
	NOT LWS_HAVE_MBEDTLS_PRIVATE_CHACHAPOLY_H))
	message(FATAL_ERROR "mbedTLS 4.x support requires TF-PSA-Crypto private headers. Add include and drivers/builtin/include from TF-PSA-Crypto to LWS_MBEDTLS_INCLUDE_DIRS.")
endif()

#
# Keep explicit parent scope exports at end
#

exports_to_parent_scope()
set(LWS_HAVE_MBEDTLS_NET_SOCKETS ${LWS_HAVE_MBEDTLS_NET_SOCKETS} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_SSL_NEW_SESSION_TICKET ${LWS_HAVE_MBEDTLS_SSL_NEW_SESSION_TICKET} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_V4 ${LWS_HAVE_MBEDTLS_V4} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_RSA_H ${LWS_HAVE_MBEDTLS_PRIVATE_RSA_H} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_ECP_H ${LWS_HAVE_MBEDTLS_PRIVATE_ECP_H} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_ECDSA_H ${LWS_HAVE_MBEDTLS_PRIVATE_ECDSA_H} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_MD5_H ${LWS_HAVE_MBEDTLS_PRIVATE_MD5_H} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_SHA1_H ${LWS_HAVE_MBEDTLS_PRIVATE_SHA1_H} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_SHA256_H ${LWS_HAVE_MBEDTLS_PRIVATE_SHA256_H} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_SHA512_H ${LWS_HAVE_MBEDTLS_PRIVATE_SHA512_H} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_AES_H ${LWS_HAVE_MBEDTLS_PRIVATE_AES_H} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_GCM_H ${LWS_HAVE_MBEDTLS_PRIVATE_GCM_H} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_CIPHER_H ${LWS_HAVE_MBEDTLS_PRIVATE_CIPHER_H} PARENT_SCOPE)
set(LWS_HAVE_MBEDTLS_PRIVATE_CHACHAPOLY_H ${LWS_HAVE_MBEDTLS_PRIVATE_CHACHAPOLY_H} PARENT_SCOPE)
