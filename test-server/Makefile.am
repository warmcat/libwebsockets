bin_PROGRAMS=libwebsockets-test-echo
libwebsockets_test_echo_SOURCES=test-echo.c
libwebsockets_test_echo_CFLAGS= -Wall -Werror -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\"
libwebsockets_test_echo_LDADD=-L../lib -lwebsockets

if NO_CLIENT
else
bin_PROGRAMS+= libwebsockets-test-client
if NO_SERVER
else
bin_PROGRAMS+= libwebsockets-test-fraggle
endif
endif

if NO_SERVER
else
bin_PROGRAMS+=libwebsockets-test-server libwebsockets-test-server-extpoll
endif

if NO_SERVER
else
libwebsockets_test_server_SOURCES=test-server.c
libwebsockets_test_server_CFLAGS=
libwebsockets_test_server_LDADD=-L../lib -lwebsockets
libwebsockets_test_server_extpoll_SOURCES=test-server.c
libwebsockets_test_server_extpoll_CFLAGS=$(AM_CFLAGS) -DEXTERNAL_POLL
libwebsockets_test_server_extpoll_LDADD=-L../lib -lwebsockets
endif
if NO_CLIENT
else
libwebsockets_test_client_SOURCES=test-client.c
libwebsockets_test_client_CFLAGS=
libwebsockets_test_client_LDADD=-L../lib -lwebsockets
if NO_SERVER
else
libwebsockets_test_fraggle_SOURCES=test-fraggle.c
libwebsockets_test_fraggle_CFLAGS=
libwebsockets_test_fraggle_LDADD=-L../lib -lwebsockets
endif
endif

if MINGW
if NO_SERVER
else
libwebsockets_test_server_CFLAGS+= -w  -I../win32port/win32helpers
libwebsockets_test_server_extpoll_CFLAGS+= -w  -I../win32port/win32helpers
endif
if NO_CLIENT
else
libwebsockets_test_client_CFLAGS+= -w   -I../win32port/win32helpers
if NO_SERVER
else
libwebsockets_test_fraggle_CFLAGS+= -w   -I../win32port/win32helpers
endif
endif

if NO_SERVER
else
libwebsockets_test_server_LDADD+= -lm -luser32 -ladvapi32 -lkernel32 -lgcc -lws2_32 -lz
libwebsockets_test_server_extpoll_LDADD+= -lm -luser32 -ladvapi32 -lkernel32 -lgcc -lws2_32 -lz
endif
if NO_CLIENT
else
libwebsockets_test_client_LDADD+= -lm -luser32 -ladvapi32 -lkernel32 -lgcc -lws2_32 -lz 
if NO_SERVER
else
libwebsockets_test_fraggle_LDADD+= -lm -luser32 -ladvapi32 -lkernel32 -lgcc -lws2_32 -lz
endif
endif

else
if NO_SERVER
else
libwebsockets_test_server_CFLAGS+= -Werror
libwebsockets_test_server_extpoll_CFLAGS+= -Werror
endif
if NO_CLIENT
else
libwebsockets_test_client_CFLAGS+= -Werror
if NO_SERVER
else
libwebsockets_test_fraggle_CFLAGS+= -Werror
endif
endif
endif   

if NO_SERVER
else
libwebsockets_test_server_CFLAGS+= -Wall -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
libwebsockets_test_server_extpoll_CFLAGS+= -Wall -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
endif
if NO_CLIENT
else
libwebsockets_test_client_CFLAGS+= -Wall -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
if NO_SERVER
else
libwebsockets_test_fraggle_CFLAGS+= -Wall -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
endif
endif

if NOPING
else
if NO_CLIENT
else
bin_PROGRAMS+=libwebsockets-test-ping
libwebsockets_test_ping_SOURCES=test-ping.c
libwebsockets_test_ping_LDADD=-L../lib -lwebsockets
libwebsockets_test_ping_CFLAGS= -Wall -Werror -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
endif
endif

EXTRA_DIST=test.html favicon.ico libwebsockets.org-logo.png leaf.jpg

#
# cook a random test cert and key
# notice your real cert and key will want to be 0600 permissions
libwebsockets-test-server.pem libwebsockets-test-server.key.pem:
	printf "GB\nErewhon\nAll around\nlibwebsockets-test\n\nlocalhost\nnone@invalid.org\n" | \
	openssl req -new -newkey rsa:1024 -days 10000 -nodes -x509 -keyout \
	./libwebsockets-test-server.key.pem -out ./libwebsockets-test-server.pem >/dev/null 2>&1  && \
	chmod 644 	./libwebsockets-test-server.key.pem \
			./libwebsockets-test-server.pem

clean-local:
	rm -f ./libwebsockets-test-server.key.pem ./libwebsockets-test-server.pem

install-data-local:libwebsockets-test-server.key.pem libwebsockets-test-server.pem
	mkdir -p $(DESTDIR)$(datadir)/libwebsockets-test-server
	cp -a $(EXTRA_DIST) libwebsockets-test-server.key.pem libwebsockets-test-server.pem \
		$(DESTDIR)$(datadir)/libwebsockets-test-server

