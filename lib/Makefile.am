@applyhash@

lib_LTLIBRARIES=libwebsockets.la
include_HEADERS=libwebsockets.h
dist_libwebsockets_la_SOURCES=libwebsockets.c \
				parsers.c \
				handshake.c \
				libwebsockets.h \
				base64-decode.c \
				output.c \
				private-libwebsockets.h

if NO_EXTENSIONS
else
dist_libwebsockets_la_SOURCES+= extension.c \
				extension-deflate-stream.c extension-deflate-stream.h \
				extension-deflate-frame.c extension-deflate-frame.h
endif

if NO_DAEMONIZE
else
dist_libwebsockets_la_SOURCES+= daemonize.c
endif

if NO_CLIENT
else
dist_libwebsockets_la_SOURCES+= client.c \
				client-parser.c \
				client-handshake.c
endif

if NO_SERVER
else
dist_libwebsockets_la_SOURCES+= server.c \
				server-handshake.c
endif

if USE_BUILTIN_GETIFADDRS
dist_libwebsockets_la_SOURCES += getifaddrs.c
endif

if LIBCRYPTO
else
dist_libwebsockets_la_SOURCES += sha-1.c
endif

libwebsockets_la_CFLAGS=-Wall -std=gnu99 -pedantic
libwebsockets_la_LDFLAGS=

# uncomment below and use cat ./lib/.libs/*.su | sort -k2g | tac
# to get a worst-first list of static stack usage if you have gcc 4.6+
#libwebsockets_la_CFLAGS+= -fstack-usage

if USE_CYASSL
libwebsockets_la_LDFLAGS+= -lcyassl
endif

if DISABLE_DEBUG
libwebsockets_la_CFLAGS+= -O4
else
libwebsockets_la_CFLAGS+= -O0 -g
endif

if MINGW
libwebsockets_la_CFLAGS+= -w -I../win32port/win32helpers -I ../win32port/zlib/
libwebsockets_la_LDFLAGS+= -lm -luser32 -ladvapi32 -lkernel32 -lgcc
else
libwebsockets_la_CFLAGS+= -rdynamic -fPIC -Werror
# notice http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html has rules for how to bump this
libwebsockets_la_LDFLAGS+=  -version-info 3:0:0
endif

libwebsockets_la_CFLAGS+= -c \
	-DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
if NO_EXTENSIONS
else
libwebsockets_la_LDFLAGS+= -lz
endif

all-local:
	 ../scripts/kernel-doc -html \
                *.c \
                libwebsockets.h \
			> ../libwebsockets-api-doc.html
	 ../scripts/kernel-doc -text \
                *.c \
                libwebsockets.h \
			> ../libwebsockets-api-doc.txt

