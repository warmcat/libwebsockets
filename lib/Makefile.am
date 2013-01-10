lib_LTLIBRARIES=libwebsockets.la
include_HEADERS=libwebsockets.h
dist_libwebsockets_la_SOURCES=libwebsockets.c \
				handshake.c \
				parsers.c \
				libwebsockets.h \
				base64-decode.c \
				client-handshake.c \
				extension.c \
				extension-deflate-stream.c extension-deflate-stream.h \
				extension-deflate-frame.c extension-deflate-frame.h\
				private-libwebsockets.h


if EXT_GOOGLE_MUX
dist_libwebsockets_la_SOURCES += extension-x-google-mux.c extension-x-google-mux.h
endif

if LIBCRYPTO
else
dist_libwebsockets_la_SOURCES += md5.c sha-1.c
endif

libwebsockets_la_CFLAGS=-Wall -std=gnu99 -pedantic
libwebsockets_la_LDFLAGS=

if MINGW
libwebsockets_la_CFLAGS+= -w -I../win32port/win32helpers -I ../win32port/zlib/
libwebsockets_la_LDFLAGS+= -lm -luser32 -ladvapi32 -lkernel32 -lgcc
else
libwebsockets_la_CFLAGS+= -rdynamic -fPIC -Werror
libwebsockets_la_LDFLAGS+=  -version-info 1:0
endif

libwebsockets_la_CFLAGS+= -c \
	-DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
libwebsockets_la_LDFLAGS+= -lz

all-local:
	 ../scripts/kernel-doc -html \
                libwebsockets.c \
		parsers.c \
		client-handshake.c \
                libwebsockets.h \
			> ../libwebsockets-api-doc.html

