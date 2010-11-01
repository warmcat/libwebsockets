export LDIR=$(shell if [ -z "gcc --print-search-dirs | grep libraries | sed s/\\//\\n/g | grep lib64 | grep 64 | head -n1" ] ; then echo lib; else echo lib64 ; fi )

all:
	gcc $(CFLAGS) libwebsockets.c
	gcc $(CFLAGS) md5.c
	gcc libwebsockets.o md5.o --shared -o libwebsockets.so
	
clean:
	rm -f *.o *.so

install:
	cp -rf libwebsockets.so $(DESTDIR)/usr/$(LDIR)
	cp -rf libwebsockets.h $(DESTDIR)/usr/include


