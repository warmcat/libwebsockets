all:
	gcc $(CFLAGS) test-server.c
	gcc  test-server.o \
		-L ../lib \
		-lwebsockets \
		-o libwebsockets-test-server

clean:
	rm -f *.o libwebsockets-test-server *.pem

install:	./libwebsockets-test-server.pem
	cp -f libwebsockets-test-server $(DESTDIR)/usr/bin
	mkdir -p $(DESTDIR)/usr/share/libwebsockets-test-server
	cp -a favicon.ico test.html libwebsockets-test-server.key.pem libwebsockets-test-server.pem $(DESTDIR)/usr/share/libwebsockets-test-server

# notice!  You would want the key chmod 600 not 644 for real install!
# this is just for test so you can run it without root easily

./libwebsockets-test-server.pem:
	printf "GB\nErewhon\nAll around\nlibwebsockets-test\n\nlocalhost\nnone@invalid.org\n" | \
	openssl req -new -newkey rsa:1024 -days 10000 -nodes -x509 -keyout \
	./libwebsockets-test-server.key.pem -out ./libwebsockets-test-server.pem >/dev/null 2>&1  && \
	chmod 644 	./libwebsockets-test-server.key.pem \
			./libwebsockets-test-server.pem

