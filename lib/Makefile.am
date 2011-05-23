lib_LTLIBRARIES=libwebsockets.la
include_HEADERS=libwebsockets.h
dist_libwebsockets_la_SOURCES=libwebsockets.c \
				handshake.c \
				parsers.c \
				libwebsockets.h \
				base64-decode.c \
				client-handshake.c \
				extension.c \
				extension-deflate-stream.c \
				private-libwebsockets.h
				
if EXT_GOOGLE_MUX
dist_libwebsockets_la_SOURCES += extension-x-google-mux.c
endif

if LIBCRYPTO
else
dist_libwebsockets_la_SOURCES += md5.c sha-1.c
endif

libwebsockets_la_CFLAGS:=-rdynamic -fPIC -Wall -Werror -std=gnu99 -pedantic -c \
	-DDATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
libwebsockets_la_LDFLAGS=-lz -version-info 0:3

all-local:
	 ../scripts/kernel-doc -html \
                libwebsockets.c \
		parsers.c \
		client-handshake.c \
                libwebsockets.h \
			> ../libwebsockets-api-doc.html

