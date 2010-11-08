lib_LTLIBRARIES=libwebsockets.la
include_HEADERS=libwebsockets.h
dist_libwebsockets_la_SOURCES=libwebsockets.c \
				handshake.c \
				parsers.c \
				md5.c \
				libwebsockets.h \
				private-libwebsockets.h
libwebsockets_la_CFLAGS=-rdynamic -fPIC -c
libwebsockets_la_LDFLAGS=-version-info 0:1

all-local:
	 ../scripts/kernel-doc -html \
                libwebsockets.c \
                parsers.c \
                ../test-server/test-server.c \
			> ../libwebsockets-api-doc.html

