lib_LTLIBRARIES=libwebsockets.la
include_HEADERS=libwebsockets.h
dist_libwebsockets_la_SOURCES=libwebsockets.c \
				handshake.c \
				parsers.c \
				libwebsockets.h \
				base64-decode.c \
				private-libwebsockets.h
libwebsockets_la_CFLAGS=-Wall -Werror -std=gnu99 -pedantic -rdynamic -fPIC -c
libwebsockets_la_LDFLAGS=-version-info 0:2 -lcrypto

all-local:
	 ../scripts/kernel-doc -html \
                libwebsockets.c \
		parsers.c \
                libwebsockets.h \
			> ../libwebsockets-api-doc.html

