export CFLAGS= -Wall -Werror -rdynamic -fPIC -c
all:
	make -C lib
	make -C test-server
	./scripts/kernel-doc -html \
		./lib/libwebsockets.c \
		./test-server/test-server.c > libwebsockets-api-doc.html

clean:
	make -C lib clean
	make -C test-server clean

install:
	make -C lib install
	make -C test-server install

	
