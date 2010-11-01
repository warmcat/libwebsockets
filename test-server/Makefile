all:
	gcc $(CFLAGS) test-server.c
	gcc  test-server.o \
		-L ../lib \
		-lwebsockets \
		-o libwebsockets-test-server

clean:
	rm -f *.o libwebsockets-test-server

install:
	cp -f libwebsockets-test-server $(DESTDIR)/usr/bin
	mkdir -p $(DESTDIR)/usr/share/libwebsockets-test-server
	cp -f favicon.ico test.html $(DESTDIR)/usr/share/libwebsockets-test-server


