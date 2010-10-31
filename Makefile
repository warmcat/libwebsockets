CFLAGS= -Wall -Werror -rdynamic -fPIC -c

all:
	gcc $(CFLAGS) libwebsockets.c
	gcc $(CFLAGS) md5.c
	gcc libwebsockets.o md5.o --shared -o libwebsockets.so
	
	gcc $(CFLAGS) test-server.c
	gcc  test-server.o ./libwebsockets.so -o test-server
	./kernel-doc -text libwebsockets.c test-server.c > \
		libwebsockets-api-doc.txt

clean:
	rm -f *.o *.so test-server
	
	
