#include "private-libwebsockets.h"
#include <netdb.h>


/*
 * In-place str to lower case
 */

void
strtolower(char *s)
{
	while (*s)
		*s++ = tolower(*s);
}

void
libwebsocket_client_close(struct libwebsocket *wsi)
{
	int n = wsi->state;
	struct libwebsocket_context *clients;

	/* mark the WSI as dead and let the callback know */

	wsi->state = WSI_STATE_DEAD_SOCKET;

	if (wsi->protocol) {
		if (wsi->protocol->callback && n == WSI_STATE_ESTABLISHED)
			wsi->protocol->callback(wsi, LWS_CALLBACK_CLOSED,
						      wsi->user_space, NULL, 0);

		/* remove it from the client polling list */
		clients = wsi->protocol->owning_server;
		if (clients)
			for (n = 0; n < clients->fds_count; n++) {
				if (clients->wsi[n] != wsi)
					continue;
				while (n < clients->fds_count - 1) {
					clients->fds[n] = clients->fds[n + 1];
					clients->wsi[n] = clients->wsi[n + 1];
				}
				/* we only have to deal with one */
				n = clients->fds_count;
			}

	}

	/* clean out any parsing allocations */

	for (n = 0; n < WSI_TOKEN_COUNT; n++)
		if (wsi->utf8_token[n].token)
			free(wsi->utf8_token[n].token);

	/* shut down reasonably cleanly */

#ifdef LWS_OPENSSL_SUPPORT
	if (use_ssl) {
		n = SSL_get_fd(wsi->ssl);
		SSL_shutdown(wsi->ssl);
		close(n);
		SSL_free(wsi->ssl);
	} else {
#endif
		shutdown(wsi->sock, SHUT_RDWR);
		close(wsi->sock);
#ifdef LWS_OPENSSL_SUPPORT
	}
#endif
}

struct libwebsocket *
libwebsocket_client_connect(struct libwebsocket_context *clients,
			      const char *address,
			      int port,
			      const char *path,
			      const char *host,
			      const char *origin,
			      const char *protocol)
{
	struct hostent *server_hostent;
	struct sockaddr_in server_addr;
	char buf[150];
	char key_b64[150];
	char hash[20];
	int fd;
	struct pollfd pfd;
	static const char magic_websocket_guid[] =
					 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	static const char magic_websocket_04_masking_guid[] =
					 "61AC5F19-FBBA-4540-B96F-6561F1AB40A8";
	char pkt[1024];
	char *p = &pkt[0];
	const char *pc;
	int len;
	int okay = 0;
	struct libwebsocket *wsi;
	int n;

	wsi = malloc(sizeof(struct libwebsocket));
	if (wsi == NULL)
		return NULL;

	clients->wsi[clients->fds_count] = wsi;

	wsi->ietf_spec_revision = 4;
	wsi->name_buffer_pos = 0;
	wsi->user_space = NULL;
	wsi->state = WSI_STATE_CLIENT_UNCONNECTED;
	wsi->pings_vs_pongs = 0;

	for (n = 0; n < WSI_TOKEN_COUNT; n++) {
		wsi->utf8_token[n].token = NULL;
		wsi->utf8_token[n].token_len = 0;
	}

	/*
	 * prepare the actual connection
	 */

	server_hostent = gethostbyname(address);
	if (server_hostent == NULL) {
		fprintf(stderr, "Unable to get host name from %s\n", address);
		goto bail1;
	}

	wsi->sock = socket(AF_INET, SOCK_STREAM, 0);

	if (wsi->sock < 0) {
		fprintf(stderr, "Unable to open socket\n");
		goto bail1;
	}


	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr = *((struct in_addr *)server_hostent->h_addr);
	bzero(&server_addr.sin_zero, 8);

	if (connect(wsi->sock, (struct sockaddr *)&server_addr,
					      sizeof(struct sockaddr)) == -1)  {
		fprintf(stderr, "Connect failed");
		goto bail1;
	}

	/*
	 * create the random key
	 */

	fd = open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);
	if (fd < 1) {
		fprintf(stderr, "Unable to open random device %s\n",
							SYSTEM_RANDOM_FILEPATH);
		goto bail2;
	}
	n = read(fd, hash, 16);
	if (n != 16) {
		fprintf(stderr, "Unable to read from random device %s\n",
							SYSTEM_RANDOM_FILEPATH);
		close(fd);
		goto bail2;
	}
	close(fd);

	lws_b64_encode_string(hash, 16, key_b64, sizeof key_b64);

	/*
	 * 04 example client handshake
	 *
	 * GET /chat HTTP/1.1
	 * Host: server.example.com
	 * Upgrade: websocket
	 * Connection: Upgrade
	 * Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
	 * Sec-WebSocket-Origin: http://example.com
	 * Sec-WebSocket-Protocol: chat, superchat
	 * Sec-WebSocket-Version: 4
	 */

	 p += sprintf(p, "GET %s HTTP/1.1\x0d\x0a", path);
	 p += sprintf(p, "Host: %s\x0d\x0a", host);
	 p += sprintf(p, "Upgrade: websocket\x0d\x0a");
	 p += sprintf(p, "Connection: Upgrade\x0d\x0aSec-WebSocket-Key: ");
	 strcpy(p, key_b64);
	 p += strlen(key_b64);
	 p += sprintf(p, "\x0d\x0aSec-WebSocket-Origin: %s\x0d\x0a", origin);
	 if (protocol != NULL)
		p += sprintf(p, "Sec-WebSocket-Protocol: %s\x0d\x0a", protocol);
	 p += sprintf(p, "Sec-WebSocket-Version: 4\x0d\x0a\x0d\x0a");


	/* prepare the expected server accept response */

	strcpy(buf, key_b64);
	strcpy(&buf[strlen(buf)], magic_websocket_guid);

	SHA1((unsigned char *)buf, strlen(buf), (unsigned char *)hash);

	lws_b64_encode_string(hash, 20, wsi->initial_handshake_hash_base64,
				  sizeof wsi->initial_handshake_hash_base64);

	/* send our request to the server */

	n = send(wsi->sock, pkt, p - pkt, 0);

	wsi->parser_state = WSI_TOKEN_NAME_PART;

	pfd.fd = wsi->sock;
	pfd.events = POLLIN;
	pfd.revents = 0;

	n = poll(&pfd, 1, 5000);
	if (n < 0) {
		fprintf(stderr, "libwebsocket_client_handshake socket error "
				"while waiting for handshake response");
		goto bail2;
	}
	if (n == 0) {
		fprintf(stderr, "libwebsocket_client_handshake timeout "
				"while waiting for handshake response");
		goto bail2;
	}

	/* interpret the server response */

	/*
	 *  HTTP/1.1 101 Switching Protocols
	 *  Upgrade: websocket
	 *  Connection: Upgrade
	 *  Sec-WebSocket-Accept: me89jWimTRKTWwrS3aRrL53YZSo=
	 *  Sec-WebSocket-Nonce: AQIDBAUGBwgJCgsMDQ4PEC==
	 *  Sec-WebSocket-Protocol: chat
	 */

	len = recv(wsi->sock, pkt, sizeof pkt, 0);
	if (len < 0) {
		fprintf(stderr, "libwebsocket_client_handshake read error\n");
		goto bail2;
	}

	p = pkt;
	for (n = 0; n < len; n++)
		libwebsocket_parse(wsi, *p++);

	if (wsi->parser_state != WSI_PARSING_COMPLETE) {
		fprintf(stderr, "libwebsocket_client_handshake server response"
				" failed parsing\n");
		goto bail2;
	}

	/*
	 * well, what the server sent looked reasonable for syntax.
	 * Now let's confirm it sent all the necessary headers
	 */

	 if (!wsi->utf8_token[WSI_TOKEN_HTTP].token_len ||
			!wsi->utf8_token[WSI_TOKEN_UPGRADE].token_len ||
			!wsi->utf8_token[WSI_TOKEN_CONNECTION].token_len ||
			!wsi->utf8_token[WSI_TOKEN_ACCEPT].token_len ||
			!wsi->utf8_token[WSI_TOKEN_NONCE].token_len ||
			(!wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len &&
							    protocol != NULL)) {
		fprintf(stderr, "libwebsocket_client_handshake "
						   "missing required header\n");
		goto bail2;
	}

	/*
	 * Everything seems to be there, now take a closer look at what is in
	 * each header
	 */

	strtolower(wsi->utf8_token[WSI_TOKEN_HTTP].token);
	if (strcmp(wsi->utf8_token[WSI_TOKEN_HTTP].token,
						   "101 switching protocols")) {
		fprintf(stderr, "libwebsocket_client_handshake server sent bad"
				" HTTP response '%s'\n",
					 wsi->utf8_token[WSI_TOKEN_HTTP].token);
		goto bail2;
	}

	strtolower(wsi->utf8_token[WSI_TOKEN_UPGRADE].token);
	if (strcmp(wsi->utf8_token[WSI_TOKEN_UPGRADE].token, "websocket")) {
		fprintf(stderr, "libwebsocket_client_handshake server sent bad"
				" Upgrade header '%s'\n",
				      wsi->utf8_token[WSI_TOKEN_UPGRADE].token);
		goto bail2;
	}

	strtolower(wsi->utf8_token[WSI_TOKEN_CONNECTION].token);
	if (strcmp(wsi->utf8_token[WSI_TOKEN_CONNECTION].token, "upgrade")) {
		fprintf(stderr, "libwebsocket_client_handshake server sent bad"
				" Connection hdr '%s'\n",
				   wsi->utf8_token[WSI_TOKEN_CONNECTION].token);
		goto bail2;
	}
	/*
	 * confirm the protocol the server wants to talk was in the list of
	 * protocols we offered
	 */

	if (!wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len) {

		/* no protocol name to work from, default to first protocol */
		wsi->protocol = &clients->protocols[0];

		goto check_accept;
	}

	pc = protocol;
	while (*pc && !okay) {
		if ((!strncmp(pc, wsi->utf8_token[WSI_TOKEN_PROTOCOL].token,
			wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len)) &&
		(pc[wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len] == ',' ||
		   pc[wsi->utf8_token[WSI_TOKEN_PROTOCOL].token_len] == '\0')) {
			okay = 1;
			continue;
		}
		while (*pc && *pc != ',')
			pc++;
		while (*pc && *pc != ' ')
			pc++;
	}
	if (!okay) {
		fprintf(stderr, "libwebsocket_client_handshake server "
					"sent bad protocol '%s'\n",
			     wsi->utf8_token[WSI_TOKEN_PROTOCOL].token);
		goto bail2;
	}

	/*
	 * identify the selected protocol struct and set it
	 */
	n = 0;
	wsi->protocol = NULL;
	while (clients->protocols[n].callback) {
		if (strcmp(wsi->utf8_token[WSI_TOKEN_PROTOCOL].token,
				       clients->protocols[n].name) == 0)
			wsi->protocol = &clients->protocols[n];
		n++;
	}

	if (wsi->protocol == NULL) {
		fprintf(stderr, "libwebsocket_client_handshake server "
				"requested protocol '%s', which we "
				"said we supported but we don't!\n",
			     wsi->utf8_token[WSI_TOKEN_PROTOCOL].token);
		goto bail2;
	}

check_accept:
	/*
	 * Confirm his accept token is the same as the one we precomputed
	 */

	if (strcmp(wsi->utf8_token[WSI_TOKEN_ACCEPT].token,
					  wsi->initial_handshake_hash_base64)) {
		fprintf(stderr, "libwebsocket_client_handshake server sent "
				"bad ACCEPT '%s' vs computed '%s'\n",
				wsi->utf8_token[WSI_TOKEN_ACCEPT].token,
					    wsi->initial_handshake_hash_base64);
		goto bail2;
	}

	/*
	 * Calculate the masking key to use when sending data to server
	 */

	strcpy(buf, key_b64);
	p = buf + strlen(key_b64);
	strcpy(p, wsi->utf8_token[WSI_TOKEN_NONCE].token);
	p += wsi->utf8_token[WSI_TOKEN_NONCE].token_len;
	strcpy(p, magic_websocket_04_masking_guid);
	SHA1((unsigned char *)buf, strlen(buf), wsi->masking_key_04);

	/* okay he is good to go */

	clients->fds[clients->fds_count].fd = wsi->sock;
	clients->fds[clients->fds_count].revents = 0;
	clients->fds[clients->fds_count++].events = POLLIN;

	wsi->state = WSI_STATE_ESTABLISHED;
	wsi->client_mode = 1;

	fprintf(stderr, "handshake OK for protocol %s\n", wsi->protocol->name);

	return wsi;


bail2:
	libwebsocket_client_close(wsi);
bail1:
	free(wsi);

	return NULL;
}
