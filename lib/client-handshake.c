#include "private-libwebsockets.h"
#include <netdb.h>


/**
 * libwebsocket_client_connect() - Connect to another websocket server
 * @context:	Websocket context
 * @address:	Remote server address, eg, "myserver.com"
 * @port:	Port to connect to on the remote server, eg, 80
 * @ssl_connection:	0 = ws://, 1 = wss:// encrypted, 2 = wss:// allow self
 *			signed certs
 * @path:	Websocket path on server
 * @host:	Hostname on server
 * @origin:	Socket origin name
 * @protocol:	Comma-separated list of protocols being asked for from
 *		the server, or just one.  The server will pick the one it
 *		likes best.
 * @ietf_version_or_minus_one: -1 to ask to connect using the default, latest
 * 		protocol supported, or the specific protocol ordinal
 *
 *	This function creates a connection to a remote server
 */

struct libwebsocket *
libwebsocket_client_connect(struct libwebsocket_context *context,
			      const char *address,
			      int port,
			      int ssl_connection,
			      const char *path,
			      const char *host,
			      const char *origin,
			      const char *protocol,
			      int ietf_version_or_minus_one)
{
	struct hostent *server_hostent;
	struct sockaddr_in server_addr;
	char pkt[512];
	struct pollfd pfd;
	struct libwebsocket *wsi;
	int n;
	int opt = 1;
	int plen = 0;
#ifndef LWS_OPENSSL_SUPPORT
	if (ssl_connection) {
		fprintf(stderr, "libwebsockets not configured for ssl\n");
		return NULL;
	}
#endif

	wsi = malloc(sizeof(struct libwebsocket));
	if (wsi == NULL)
		goto bail1;

	memset(wsi, 0, sizeof *wsi);

	/* -1 means just use latest supported */

	if (ietf_version_or_minus_one == -1)
		ietf_version_or_minus_one = SPEC_LATEST_SUPPORTED;

	wsi->ietf_spec_revision = ietf_version_or_minus_one;
	wsi->name_buffer_pos = 0;
	wsi->user_space = NULL;
	wsi->state = WSI_STATE_CLIENT_UNCONNECTED;
	wsi->pings_vs_pongs = 0;
	wsi->protocol = NULL;
	wsi->pending_timeout = NO_PENDING_TIMEOUT;
	wsi->count_active_extensions = 0;
#ifdef LWS_OPENSSL_SUPPORT
	wsi->use_ssl = ssl_connection;
#endif

	/* copy parameters over so state machine has access */

	wsi->c_path = malloc(strlen(path) + 1);
	if (wsi->c_path == NULL)
		goto bail1;
	strcpy(wsi->c_path, path);
	wsi->c_host = malloc(strlen(host) + 1);
	if (wsi->c_host == NULL)
		goto oom1;
	strcpy(wsi->c_host, host);
	if (origin) {
		wsi->c_origin = malloc(strlen(origin) + 1);
		strcpy(wsi->c_origin, origin);
		if (wsi->c_origin == NULL)
			goto oom2;
	} else
		wsi->c_origin = NULL;
	if (protocol) {
		wsi->c_protocol = malloc(strlen(protocol) + 1);
		if (wsi->c_protocol == NULL)
			goto oom3;
		strcpy(wsi->c_protocol, protocol);
	} else
		wsi->c_protocol = NULL;


	/* set up appropriate masking */

	wsi->xor_mask = xor_no_mask;

	switch (wsi->ietf_spec_revision) {
	case 0:
		break;
	case 4:
		wsi->xor_mask = xor_mask_04;
		break;
	case 5:
	case 6:
	case 7:
		wsi->xor_mask = xor_mask_05;
		break;
	default:
		fprintf(stderr,
			"Client ietf version %d not supported\n",
						       wsi->ietf_spec_revision);
		goto oom4;
	}

	/* force no mask if he asks for that though */

	if (context->options & LWS_SERVER_OPTION_DEFEAT_CLIENT_MASK)
		wsi->xor_mask = xor_no_mask;

	for (n = 0; n < WSI_TOKEN_COUNT; n++) {
		wsi->utf8_token[n].token = NULL;
		wsi->utf8_token[n].token_len = 0;
	}

	/*
	 * proxy?
	 */

	if (context->http_proxy_port) {
		plen = sprintf(pkt, "CONNECT %s:%u HTTP/1.0\x0d\x0a"
			"User-agent: libwebsockets\x0d\x0a"
/*Proxy-authorization: basic aGVsbG86d29ybGQ= */
			"\x0d\x0a", address, port);

		/* OK from now on we talk via the proxy */

		address = context->http_proxy_address;
		port = context->http_proxy_port;
	}

	/*
	 * prepare the actual connection (to the proxy, if any)
	 */

	server_hostent = gethostbyname(address);
	if (server_hostent == NULL) {
		fprintf(stderr, "Unable to get host name from %s\n", address);
		goto oom4;
	}

	wsi->sock = socket(AF_INET, SOCK_STREAM, 0);

	if (wsi->sock < 0) {
		fprintf(stderr, "Unable to open socket\n");
		goto oom4;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr = *((struct in_addr *)server_hostent->h_addr);
	bzero(&server_addr.sin_zero, 8);

	/* Disable Nagle */
	setsockopt(wsi->sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

	if (connect(wsi->sock, (struct sockaddr *)&server_addr,
					      sizeof(struct sockaddr)) == -1)  {
		fprintf(stderr, "Connect failed\n");
		goto oom4;
	}

	/* into fd -> wsi hashtable */

	insert_wsi(context, wsi);

	/* into internal poll list */

	context->fds[context->fds_count].fd = wsi->sock;
	context->fds[context->fds_count].revents = 0;
	context->fds[context->fds_count++].events = POLLIN;

	/* external POLL support via protocol 0 */
	context->protocols[0].callback(context, wsi,
		LWS_CALLBACK_ADD_POLL_FD,
		(void *)(long)wsi->sock, NULL, POLLIN);

	/* we are connected to server, or proxy */

	if (context->http_proxy_port) {

		n = send(wsi->sock, pkt, plen, 0);
		if (n < 0) {
#ifdef WIN32
			closesocket(wsi->sock);
#else
			close(wsi->sock);
#endif
			fprintf(stderr, "ERROR writing to proxy socket\n");
			goto bail1;
		}

		libwebsocket_set_timeout(wsi,
			PENDING_TIMEOUT_AWAITING_PROXY_RESPONSE, 5);

		wsi->mode = LWS_CONNMODE_WS_CLIENT_WAITING_PROXY_REPLY;

		return wsi;
	}

	/*
	 * provoke service to issue the handshake directly
	 * we need to do it this way because in the proxy case, this is the
	 * next state and executed only if and when we get a good proxy
	 * response inside the state machine
	 */

	wsi->mode = LWS_CONNMODE_WS_CLIENT_ISSUE_HANDSHAKE;
	pfd.fd = wsi->sock;
	pfd.revents = POLLIN;
	libwebsocket_service_fd(context, &pfd);

	return wsi;

oom4:
	if (wsi->c_protocol)
		free(wsi->c_protocol);

oom3:
	if (wsi->c_origin)
		free(wsi->c_origin);

oom2:
	free(wsi->c_host);

oom1:
	free(wsi->c_path);

bail1:
	free(wsi);

	return NULL;
}
