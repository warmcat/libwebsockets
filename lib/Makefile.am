lib_LTLIBRARIES=libwebsockets.la
include_HEADERS=libwebsockets.h
dist_libwebsockets_la_SOURCES=libwebsockets.c \
				handshake.c \
				parsers.c \
				libwebsockets.h \
				base64-decode.c \
				client-handshake.c \
				private-libwebsockets.h
if LIBCRYPTO
else
dist_libwebsockets_la_SOURCES += md5.c sha-1.c
endif

libwebsockets_la_CFLAGS=-Wall -Werror -std=gnu99 -pedantic -rdynamic -fPIC -c
libwebsockets_la_LDFLAGS=-version-info 0:2

all-local:
	 ../scripts/kernel-doc -html \
                libwebsockets.c \
		parsers.c \
		client-handshake.c \
                libwebsockets.h \
			> ../libwebsockets-api-doc.html

