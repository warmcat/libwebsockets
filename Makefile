all:
	gcc -Wall -Werror -rdynamic -fPIC -c libwebsockets.c
	gcc -Wall -Werror -rdynamic -fPIC -c md5.c
	gcc libwebsockets.o md5.o --shared -o libwebsockets.so

clean:
	rm -f *.o *.so
	
