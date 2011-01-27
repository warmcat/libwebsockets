bin_PROGRAMS=libwebsockets-test-server libwebsockets-test-client
libwebsockets_test_server_SOURCES=test-server.c
libwebsockets_test_server_LDADD=-L../lib -lwebsockets
libwebsockets_test_client_SOURCES=test-client.c
libwebsockets_test_client_LDADD=-L../lib -lwebsockets



libwebsockets_test_server_CFLAGS:= -Wall -Werror -std=gnu99 -pedantic -DDATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"
libwebsockets_test_client_CFLAGS:= -Wall -Werror -std=gnu99 -pedantic -DDATADIR=\"@datadir@\" -DLWS_OPENSSL_CLIENT_CERTS=\"@clientcertdir@\"

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

