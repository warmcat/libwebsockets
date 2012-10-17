bin_PROGRAMS=libwebsockets-test-server libwebsockets-test-client libwebsockets-test-server-extpoll libwebsockets-test-fraggle
libwebsockets_test_server_SOURCES=test-server.c
libwebsockets_test_server_LDADD=-L../lib -lwebsockets -lz
libwebsockets_test_client_SOURCES=test-client.c
libwebsockets_test_client_LDADD=-L../lib -lwebsockets -lz
libwebsockets_test_server_extpoll_SOURCES=test-server-extpoll.c
libwebsockets_test_server_extpoll_LDADD=-L../lib -lwebsockets -lz
libwebsockets_test_fraggle_SOURCES=test-fraggle.c
libwebsockets_test_fraggle_LDADD=-L../lib -lwebsockets -lz
 
if MINGW                                                                        
libwebsockets_test_server_CFLAGS= -w  -I../win32port/win32helpers
libwebsockets_test_client_CFLAGS= -w   -I../win32port/win32helpers
libwebsockets_test_server_extpoll_CFLAGS= -w  -I../win32port/win32helpers
libwebsockets_test_fraggle_CFLAGS= -w   -I../win32port/win32helpers

libwebsockets_test_server_LDADD+= -lm -luser32 -ladvapi32 -lkernel32 -lgcc -lws2_32 -lz
libwebsockets_test_client_LDADD+= -lm -luser32 -ladvapi32 -lkernel32 -lgcc -lws2_32 -lz 
libwebsockets_test_server_extpoll_LDADD+= -lm -luser32 -ladvapi32 -lkernel32 -lgcc -lws2_32 -lz
libwebsockets_test_fraggle_LDADD+= -lm -luser32 -ladvapi32 -lkernel32 -lgcc -lws2_32 -lz

else
libwebsockets_test_server_CFLAGS= -Werror
libwebsockets_test_client_CFLAGS= -Werror
libwebsockets_test_server_extpoll_CFLAGS= -Werror
libwebsockets_test_fraggle_CFLAGS= -Werror
endif   

libwebsockets_test_server_CFLAGS+= -Wall -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
libwebsockets_test_client_CFLAGS+= -Wall -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
libwebsockets_test_server_extpoll_CFLAGS+= -Wall -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
libwebsockets_test_fraggle_CFLAGS+= -Wall -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"


if NOPING
else
bin_PROGRAMS+=libwebsockets-test-ping
libwebsockets_test_ping_SOURCES=test-ping.c
libwebsockets_test_ping_LDADD=-L../lib -lwebsockets
libwebsockets_test_ping_CFLAGS= -Wall -Werror -std=gnu99 -pedantic -DINSTALL_DATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
endif

EXTRA_DIST=test.html favicon.ico

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
	cp -a test.html favicon.ico libwebsockets-test-server.key.pem libwebsockets-test-server.pem \
		$(DESTDIR)$(datadir)/libwebsockets-test-server

