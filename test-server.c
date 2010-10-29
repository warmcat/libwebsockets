#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libwebsockets.h"

#define PORT 7681

int websocket_callback(struct libwebsocket * wsi,
				      enum libwebsocket_callback_reasons reason)
{
	int n;
	char buf[256];
	static int bump;
	
	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		fprintf(stderr, "Websocket connection established\n");
		break;

	case LWS_CALLBACK_CLOSED:
		fprintf(stderr, "Websocket connection closed\n");
		break;

	case LWS_CALLBACK_SEND:	
		sleep(1);
		n = sprintf(buf, "%d\n", bump++);
		n = libwebsocket_write(wsi, buf, n);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			exit(1);
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		break;
	}
	return 0;
}


int main(int argv, char **argc)
{
	if (libwebsocket_create_server(PORT, websocket_callback) < 0) {
		fprintf(stderr, "libwebsocket init failed\n");
		return -1;
	}
	
	fprintf(stderr, "Listening on port %d\n", PORT);
	
	while (1)
		sleep(1);

	return 0;
}
