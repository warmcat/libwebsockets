#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#include <poll.h>
#include <sys/mman.h>

#include "libwebsockets.h"

void md5(const unsigned char *input, int ilen, unsigned char output[16]);
static void libwebsocket_service(struct libwebsocket *wsi, int sock);

#define LWS_MAX_HEADER_NAME_LENGTH 64
#define LWS_MAX_HEADER_LEN 4096
#define LWS_INITIAL_HDR_ALLOC 256
#define LWS_ADDITIONAL_HDR_ALLOC 64


enum lws_connection_states {
	WSI_STATE_CLOSED,
	WSI_STATE_HANDSHAKE_RX,
	WSI_STATE_DEAD_SOCKET,
	WSI_STATE_ESTABLISHED
};

enum lws_token_indexes {
	WSI_TOKEN_GET_URI,
	WSI_TOKEN_HOST,
	WSI_TOKEN_CONNECTION,
	WSI_TOKEN_KEY1,
	WSI_TOKEN_KEY2,
	WSI_TOKEN_PROTOCOL,
	WSI_TOKEN_UPGRADE,
	WSI_TOKEN_ORIGIN,
	WSI_TOKEN_CHALLENGE,
	
	/* always last real token index*/
	WSI_TOKEN_COUNT,
	/* parser state additions */
	WSI_TOKEN_NAME_PART,
	WSI_TOKEN_SKIPPING,
	WSI_TOKEN_SKIPPING_SAW_CR,
	WSI_PARSING_COMPLETE
};


struct lws_tokens {
	char * token;
	int token_len;
};


/*
 * This is totally opaque to code using the library.  It's exported as a
 * forward-reference pointer-only declaration.
 */

struct libwebsocket {
	int (*callback)(struct libwebsocket *,
				     enum libwebsocket_callback_reasons reason);

	enum lws_connection_states state;

	char name_buffer[LWS_MAX_HEADER_NAME_LENGTH];
	int name_buffer_pos;
	int current_alloc_len;
	enum lws_token_indexes parser_state;
	struct lws_tokens utf8_token[WSI_TOKEN_COUNT];
	int ietf_spec_revision;
	
	int sock;
};


const struct lws_tokens lws_tokens[WSI_TOKEN_COUNT] = {
	{ "GET ", 4 },
	{ "Host:", 5 },
	{ "Connection:", 11 },
	{ "Sec-WebSocket-Key1:", 19 },
	{ "Sec-WebSocket-Key2:", 19 },
	{ "Sec-WebSocket-Protocol:", 23 },
	{ "Upgrade:", 8 },
	{ "Origin:", 7 },
	{ "\x0d\x0a", 2 },
};

int libwebsocket_create_server(int port, int (*callback)(struct libwebsocket *, enum libwebsocket_callback_reasons))
{
	int n;
	int sockfd, newsockfd;
	unsigned int clilen;
	struct sockaddr_in serv_addr, cli_addr;
	int pid;
	struct libwebsocket *wsi = malloc(sizeof(struct libwebsocket));
     
	if (!wsi)
		return -1;
     
	wsi->state = WSI_STATE_CLOSED;
	wsi->name_buffer_pos = 0;

	for (n = 0; n < WSI_TOKEN_COUNT; n++) {
		wsi->utf8_token[n].token = NULL;
		wsi->utf8_token[n].token_len = 0;
	}
	
	wsi->callback = callback;
	wsi->ietf_spec_revision = 0;
 
	/* sit there listening for connects, accept and spawn session servers */
 
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		fprintf(stderr, "ERROR opening socket");
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	n = bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if (n < 0) {
              fprintf(stderr, "ERROR on binding %d %d\n", n, errno);
              return -1;
        }
 
 	/* fork off a master server for this websocket server */
 
	n = fork();
	if (n < 0) {
		fprintf(stderr, "Failed on forking server thread: %d\n", n);
		exit(1);
	}
	
	/* we are done as far as the caller is concerned */
	
	if (n)
		return 0;
 
              
	listen(sockfd, 5);
    
	while (1) {
		clilen = sizeof(cli_addr);

		 newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		 if (newsockfd < 0) {
			fprintf(stderr, "ERROR on accept");
			continue;
		}
			
		/* fork off a new server instance */
			
		 pid = fork();
		 if (pid < 0) {
			fprintf(stderr, "ERROR on fork");
			continue;
		}
		
		if (pid) {
			close(newsockfd);
			continue;
		}

		/* we are the session process */

		close(sockfd);
		
		/* sit in libwebsocket_service() until session socket closed */
		
		libwebsocket_service(wsi, newsockfd);
		exit(0);
	}
}

void libwebsocket_close(struct libwebsocket *wsi)
{
	int n;

	wsi->state = WSI_STATE_DEAD_SOCKET;

	if (wsi->callback)
		wsi->callback(wsi, LWS_CALLBACK_CLOSED);

	for (n = 0; n < WSI_TOKEN_COUNT; n++)
		if (wsi->utf8_token[n].token)
			free(wsi->utf8_token[n].token);
}


static int libwebsocket_parse(struct libwebsocket *wsi, unsigned char c)
{
	int n;

	switch (wsi->parser_state) {
	case WSI_TOKEN_GET_URI:
	case WSI_TOKEN_HOST:
	case WSI_TOKEN_CONNECTION:
	case WSI_TOKEN_KEY1:
	case WSI_TOKEN_KEY2:
	case WSI_TOKEN_PROTOCOL:
	case WSI_TOKEN_UPGRADE:
	case WSI_TOKEN_ORIGIN:
	case WSI_TOKEN_CHALLENGE:
	
//		fprintf(stderr, "WSI_TOKEN_(body %d) '%c'\n", wsi->parser_state, c);

		/* collect into malloc'd buffers */
		/* optional space swallow */
		if (!wsi->utf8_token[wsi->parser_state].token_len && c == ' ')
			break;
			
		/* special case space terminator for get-uri */
		if (wsi->parser_state == WSI_TOKEN_GET_URI && c == ' ') {
			wsi->utf8_token[wsi->parser_state].token[
			   wsi->utf8_token[wsi->parser_state].token_len] = '\0';
			wsi->parser_state = WSI_TOKEN_SKIPPING;
			break;
		}

		/* allocate appropriate memory */
		if (wsi->utf8_token[wsi->parser_state].token_len == wsi->current_alloc_len - 1) {
			/* need to extend */
			wsi->current_alloc_len += LWS_ADDITIONAL_HDR_ALLOC;
			if (wsi->current_alloc_len >= LWS_MAX_HEADER_LEN) {
				/* it's waaay to much payload, fail it */
				strcpy(wsi->utf8_token[wsi->parser_state].token,
				    "!!! Length exceeded maximum supported !!!");
				wsi->parser_state = WSI_TOKEN_SKIPPING;
				break;
			}
			wsi->utf8_token[wsi->parser_state].token =
			       realloc(wsi->utf8_token[wsi->parser_state].token,
							wsi->current_alloc_len);
		}

		/* bail at EOL */
		if (wsi->parser_state != WSI_TOKEN_CHALLENGE && c == '\x0d') {
			wsi->utf8_token[wsi->parser_state].token[
			   wsi->utf8_token[wsi->parser_state].token_len] = '\0';
			wsi->parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
			break;
		}

		wsi->utf8_token[wsi->parser_state].token[
			    wsi->utf8_token[wsi->parser_state].token_len++] = c;

		/* special payload limiting */
		if (wsi->parser_state == WSI_TOKEN_CHALLENGE &&
			    wsi->utf8_token[wsi->parser_state].token_len == 8) {
//			fprintf(stderr, "Setting WSI_PARSING_COMPLETE\n");
			wsi->parser_state = WSI_PARSING_COMPLETE;
			break;
		}
		
		break;

		/* collecting and checking a name part */
	case WSI_TOKEN_NAME_PART:
//		fprintf(stderr, "WSI_TOKEN_NAME_PART '%c'\n", c);

		if (wsi->name_buffer_pos == sizeof(wsi->name_buffer) - 1) {
			/* name bigger than we can handle, skip until next */
			wsi->parser_state = WSI_TOKEN_SKIPPING;
			break;
		}
		wsi->name_buffer[wsi->name_buffer_pos++] = c;
		wsi->name_buffer[wsi->name_buffer_pos] = '\0';
		
		for (n = 0; n < WSI_TOKEN_COUNT; n++) {
			if (wsi->name_buffer_pos != lws_tokens[n].token_len)
				continue;
			if (strcmp(lws_tokens[n].token, wsi->name_buffer))
				continue;
			wsi->parser_state = WSI_TOKEN_GET_URI + n;
			wsi->current_alloc_len = LWS_INITIAL_HDR_ALLOC;
			wsi->utf8_token[wsi->parser_state].token =
						 malloc(wsi->current_alloc_len);
			wsi->utf8_token[wsi->parser_state].token_len = 0;
			n = WSI_TOKEN_COUNT;
		}
		if (wsi->parser_state != WSI_TOKEN_NAME_PART)
			break;
		break;
			
		/* skipping arg part of a name we didn't recognize */
	case WSI_TOKEN_SKIPPING:
//		fprintf(stderr, "WSI_TOKEN_SKIPPING '%c'\n", c);
		if (c == '\x0d')
			wsi->parser_state = WSI_TOKEN_SKIPPING_SAW_CR;
		break;
	case WSI_TOKEN_SKIPPING_SAW_CR:
//		fprintf(stderr, "WSI_TOKEN_SKIPPING_SAW_CR '%c'\n", c);
		if (c == '\x0a')
			wsi->parser_state = WSI_TOKEN_NAME_PART;
		else
			wsi->parser_state = WSI_TOKEN_SKIPPING;
		wsi->name_buffer_pos = 0;
		break;
		/* we're done, ignore anything else */
	case WSI_PARSING_COMPLETE:
//		fprintf(stderr, "WSI_PARSING_COMPLETE '%c'\n", c);
		break;
		
	default:	/* keep gcc happy */
		break;
	}
	
	return 0;
}

static int interpret_key(const char *key, unsigned int *result)
{
	char digits[20];
	int digit_pos = 0;
	const char *p = key;
	int spaces = 0;
	
	while (*p) {
		if (isdigit(*p)) {
			if (digit_pos == sizeof(digits) - 1)
				return -1;
			digits[digit_pos++] = *p;
		}
		p++;
	}
	digits[digit_pos] = '\0';
	if (!digit_pos)
		return -2;
		
	while (*key) {
		if (*key == ' ')
			spaces++;
		key++;
	}
	
	if (!spaces)
		return -3;
		
	*result = atol(digits) / spaces;
	
	return 0;
}


/*
 * We have to take care about parsing because the headers may be split
 * into multiple fragments.  They may contain unknown headers with arbitrary
 * argument lengths.  So, we parse using a single-character at a time state
 * machine that is completely independent of packet size.
 */

int libwebsocket_read(struct libwebsocket *wsi, unsigned char * buf, size_t len)
{
	size_t n;
	char *p;
	unsigned int key1, key2;
	unsigned char sum[16];
	char *response;
	
	switch (wsi->state) {
	case WSI_STATE_CLOSED:
		wsi->state = WSI_STATE_HANDSHAKE_RX;
		wsi->parser_state = WSI_TOKEN_NAME_PART;
		/* fallthru */
	case WSI_STATE_HANDSHAKE_RX:
	
		fprintf(stderr, "issuing %ld bytes to parser\n", len);
	
	
		fwrite(buf, 1, len, stderr);
		for (n = 0; n< len; n++)
			libwebsocket_parse(wsi, *buf++);
			
		if (wsi->parser_state != WSI_PARSING_COMPLETE)
			break;
			
		fprintf(stderr, "Preparing return packet\n");


		/* Confirm we have all the necessary pieces */
		
		if (
			!wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len ||
			!wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len ||
			!wsi->utf8_token[WSI_TOKEN_ORIGIN].token_len ||
			!wsi->utf8_token[WSI_TOKEN_HOST].token_len ||
			!wsi->utf8_token[WSI_TOKEN_CHALLENGE].token_len ||
			!wsi->utf8_token[WSI_TOKEN_KEY1].token_len ||
			!wsi->utf8_token[WSI_TOKEN_KEY2].token_len) {
				
			/* completed header processing, but missing some bits */
			goto bail;
		}
		
		/* create the response packet */
		
		response = malloc(256 +
			wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len +
			wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len +
			wsi->utf8_token[WSI_TOKEN_HOST].token_len +
			wsi->utf8_token[WSI_TOKEN_ORIGIN].token_len +
			wsi->utf8_token[WSI_TOKEN_GET_URI].token_len +
			wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len);
		
		
		fprintf(stderr, "'%s;\n", wsi->utf8_token[WSI_TOKEN_HOST].token);
		
		p = response;
		strcpy(p,   "HTTP/1.1 101 WebSocket Protocol Handshake\x0d\x0aUpgrade: WebSocket\x0d\x0a");
		p += strlen("HTTP/1.1 101 WebSocket Protocol Handshake\x0d\x0aUpgrade: WebSocket\x0d\x0a");
		strcpy(p,   "Connection: Upgrade\x0d\x0aSec-WebSocket-Origin: ");
		p += strlen("Connection: Upgrade\x0d\x0aSec-WebSocket-Origin: ");
		strcpy(p, wsi->utf8_token[WSI_TOKEN_ORIGIN].token);
		p += wsi->utf8_token[WSI_TOKEN_ORIGIN].token_len;
		strcpy(p,   "\x0d\x0aSec-WebSocket-Location: ws://");
		p += strlen("\x0d\x0aSec-WebSocket-Location: ws://");
		strcpy(p, wsi->utf8_token[WSI_TOKEN_HOST].token);
		p += wsi->utf8_token[WSI_TOKEN_HOST].token_len;
		strcpy(p, wsi->utf8_token[WSI_TOKEN_GET_URI].token);
		p += wsi->utf8_token[WSI_TOKEN_GET_URI].token_len;
		strcpy(p,   "\x0d\x0aSec-WebSocket-Protocol: ");
		p += strlen("\x0d\x0aSec-WebSocket-Protocol: ");
		if (wsi->utf8_token[WSI_TOKEN_PROTOCOL].token) {
			strcpy(p, wsi->utf8_token[WSI_TOKEN_PROTOCOL].token);
			p += wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len;
		} else {
			strcpy(p,   "none");
			p += strlen("none");
		}
		strcpy(p,   "\x0d\x0a\x0d\x0a");
		p += strlen("\x0d\x0a\x0d\x0a");
		
		/* convert the two keys into 32-bit integers */
		
		if (interpret_key(wsi->utf8_token[WSI_TOKEN_KEY1].token, &key1))
			goto bail;

		if (interpret_key(wsi->utf8_token[WSI_TOKEN_KEY2].token, &key2))
			goto bail;
			
		/* lay them out in network byte order (MSB first */

		sum[0] = key1 >> 24;
		sum[1] = key1 >> 16;
		sum[2] = key1 >> 8;
		sum[3] = key1;
		sum[4] = key2 >> 24;
		sum[5] = key2 >> 16;
		sum[6] = key2 >> 8;
		sum[7] = key2;
		
		/* follow them with the challenge token we were sent */
		
		memcpy(&sum[8], wsi->utf8_token[WSI_TOKEN_CHALLENGE].token, 8);

		/* 
		 * compute the md5sum of that 16-byte series and use as our
		 * payload after our headers
		 */

		md5(sum, 16, (unsigned char *)p);
		p += 16;

		/* it's complete, go ahead and send it */
		
		fprintf(stderr, "issuing response packet %d len\n",
							  (int)(p - response));
		fwrite(response, 1,  p - response, stderr);
			
		n = write(wsi->sock, response, p - response);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			goto bail;
		}

		free(response);
		wsi->state = WSI_STATE_ESTABLISHED;
		
		/* notify user code that we're ready to roll */
				
		if (wsi->callback)
			wsi->callback(wsi, LWS_CALLBACK_ESTABLISHED);
		break;

	case WSI_STATE_ESTABLISHED:
		fprintf(stderr, "received %ld byte packet\n", len);
		break;
	default:
		break;
	}
	
	return 0;
	
bail:
	libwebsocket_close(wsi);
	return -1;
}

int libwebsocket_write(struct libwebsocket * wsi, void *buf, size_t len)
{
	int n;
	unsigned char hdr[9];
	
	if (wsi->state != WSI_STATE_ESTABLISHED)
		return -1;

	switch (wsi->ietf_spec_revision) {
	/* chrome */
	case 0:
		hdr[0] = 0xff;
		hdr[1] = len >> 56;
		hdr[2] = len >> 48;
		hdr[3] = len >> 40;
		hdr[4] = len >> 32;
		hdr[5] = len >> 24;
		hdr[6] = len >> 16;
		hdr[7] = len >> 8;
		hdr[8] = len;

		n = write(wsi->sock, hdr, sizeof hdr);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			return -1;
		}
		break;
	/* just an unimplemented spec right now apparently */
	case 2:
		n = 0;
		if (len < 126) {
			hdr[n++] = 0x04;
			hdr[n++] = len;
		} else {
			if (len < 65536) {
				hdr[n++] = 0x04; /* text frame */
				hdr[n++] = 126;
				hdr[n++] = len >> 8;
				hdr[n++] = len;
			} else {
				hdr[n++] = 0x04;
				hdr[n++] = 127;
				hdr[n++] = len >> 24;
				hdr[n++] = len >> 16;
				hdr[n++] = len >> 8;
				hdr[n++] = len;
			}
		}
		n = write(wsi->sock, hdr, n);
		if (n < 0) {
			fprintf(stderr, "ERROR writing to socket");
			return -1;
		}
		break;
	}

	n = write(wsi->sock, buf, len);
	if (n < 0) {
		fprintf(stderr, "ERROR writing to socket");
		return -1;
	}
	
	fprintf(stderr, "written %d bytes to websocket\n", (int)len);
	
	return 0;
}

static void libwebsocket_service(struct libwebsocket *wsi, int sock)
{
	int n;
	unsigned char buf[256];
	struct pollfd fds;
	
	wsi->sock = sock;
	
	fds.fd = sock;
	fds.events = POLLIN | POLLOUT;
      
	while (1) {
		
		n = poll(&fds, 1, 10);
		if (n < 0) {
			fprintf(stderr, "Socket dead (poll = %d)\n", n);
			return;
		}

		if (fds.revents & (POLLERR | POLLHUP)) {
			fprintf(stderr, "Socket dead\n");
			return;
		}
		
		if (wsi->state == WSI_STATE_DEAD_SOCKET)
			return;
		
		
		if (fds.revents & POLLIN) {
			
//			fprintf(stderr, "POLLIN\n");
			
			n = read(sock, buf, sizeof(buf));
			if (n < 0) {
				fprintf(stderr, "Socket read returned %d\n", n);
				continue;
			}
			if (n)
				libwebsocket_read(wsi, buf, n);
		}
		
		if (wsi->state != WSI_STATE_ESTABLISHED)
			continue;
		
		if (wsi->callback)
			wsi->callback(wsi, LWS_CALLBACK_SEND);
	}
}

