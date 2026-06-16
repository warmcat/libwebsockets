/*
 * lws-api-test-openhitls-gendtls
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

#if defined(WIN32) || defined(_WIN32)
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define compatible_close closesocket
#define compatible_file_close _close
#define compatible_read _read
#define compatible_fstat _fstat
#define lws_usleep(x) Sleep((x) / 1000)
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define compatible_close close
#define compatible_file_close close
#define compatible_read read
#define compatible_fstat fstat
#define lws_usleep(x) usleep(x)
#endif

enum {
	LWS_SW_PORT,
	LWS_SW_UDP,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]	= { "--port",	"Port to connect or listen on" },
	[LWS_SW_UDP]	= { "--udp",	"Use UDP sockets between DTLS peers" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

static const struct lws_context_creation_info info = {
	.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT,
};

static int
read_file_into_mem(const char *path, uint8_t **buf, size_t *len)
{
	struct stat st;
	size_t pos = 0;
	int fd;

	fd = lws_open(path, LWS_O_RDONLY);
	if (fd < 0)
		return -1;

	if (compatible_fstat(fd, &st) || st.st_size <= 0) {
		compatible_file_close(fd);
		return -1;
	}

	*buf = malloc((size_t)st.st_size + 1);
	if (!*buf) {
		compatible_file_close(fd);
		return -1;
	}

	while (pos < (size_t)st.st_size) {
		int n = (int)compatible_read(fd, *buf + pos,
					     (size_t)st.st_size - pos);

		if (n <= 0) {
			free(*buf);
			*buf = NULL;
			compatible_file_close(fd);
			return -1;
		}

		pos += (size_t)n;
	}

	(*buf)[pos] = '\0';
	*len = pos + 1;
	compatible_file_close(fd);

	return 0;
}

static int
load_test_cert_key(uint8_t **cert_mem, size_t *cert_len, uint8_t **key_mem,
		   size_t *key_len)
{
	static const char * const paths[] = {
		"./",
		LWS_INSTALL_DATADIR "/libwebsockets-test-server/",
		"",
		"../",
		"../../",
		"bin/share/libwebsockets-test-server/",
		"../../share/libwebsockets-test-server/",
		"../../../share/libwebsockets-test-server/"
	};
	char cert_path[256], key_path[256];
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(paths); n++) {
		lws_snprintf(cert_path, sizeof(cert_path),
			     "%slibwebsockets-test-server.pem", paths[n]);
		lws_snprintf(key_path, sizeof(key_path),
			     "%slibwebsockets-test-server.key.pem", paths[n]);

		if (!read_file_into_mem(cert_path, cert_mem, cert_len) &&
		    !read_file_into_mem(key_path, key_mem, key_len)) {
			lwsl_notice("%s: loaded certs from %s\n", __func__,
				    paths[n]);
			return 0;
		}

		if (*cert_mem) {
			free(*cert_mem);
			*cert_mem = NULL;
			*cert_len = 0;
		}
		if (*key_mem) {
			free(*key_mem);
			*key_mem = NULL;
			*key_len = 0;
		}
	}

	return -1;
}

static lws_sockfd_type
udp_socket(int port, struct sockaddr_in *bound)
{
	lws_sockfd_type fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);

	if (fd == LWS_SOCK_INVALID)
		return LWS_SOCK_INVALID;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)port);
	sin.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		compatible_close(fd);
		return LWS_SOCK_INVALID;
	}

	if (bound) {
		if (getsockname(fd, (struct sockaddr *)&sin, &len) < 0) {
			compatible_close(fd);
			return LWS_SOCK_INVALID;
		}
		*bound = sin;
	}

	return fd;
}

static int
move_record(struct lws_gendtls_ctx *src, struct lws_gendtls_ctx *dst,
	    uint8_t *buf, size_t buflen, int use_udp,
	    lws_sockfd_type tx_fd, lws_sockfd_type rx_fd,
	    struct sockaddr_in *tx_addr, struct sockaddr_in *rx_addr,
	    socklen_t *rx_addr_len)
{
	int n = lws_gendtls_get_tx(src, buf, buflen);

	if (n < 0)
		return -1;

	if (!n)
		return 0;

	if (use_udp) {
		ssize_t r;

		if (sendto(tx_fd, buf, (size_t)n, 0,
			   (struct sockaddr *)tx_addr, sizeof(*tx_addr)) != n)
			return -1;

		r = recvfrom(rx_fd, buf, buflen, 0,
			     (struct sockaddr *)rx_addr, rx_addr_len);
		if (r <= 0)
			return -1;

		return lws_gendtls_put_rx(dst, buf, (size_t)r);
	}

	return lws_gendtls_put_rx(dst, buf, (size_t)n);
}

static int
drive_pair(struct lws_gendtls_ctx *client, struct lws_gendtls_ctx *server,
	   int use_udp, int port)
{
	lws_sockfd_type client_fd = LWS_SOCK_INVALID;
	lws_sockfd_type server_fd = LWS_SOCK_INVALID;
	struct sockaddr_in srv_addr, cli_addr;
	socklen_t cli_len = sizeof(cli_addr);
	uint8_t buf[2048];
	int n;

	memset(&srv_addr, 0, sizeof(srv_addr));
	memset(&cli_addr, 0, sizeof(cli_addr));

	if (use_udp) {
		server_fd = udp_socket(port, &srv_addr);
		client_fd = udp_socket(0, NULL);
		if (server_fd == LWS_SOCK_INVALID ||
		    client_fd == LWS_SOCK_INVALID)
			goto bail;

		inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);
	}

	for (n = 0; n < 300; n++) {
		lws_usleep(10000);

		if (move_record(client, server, buf, sizeof(buf), use_udp,
				client_fd, server_fd, &srv_addr, &cli_addr,
				&cli_len))
			goto bail;

		if (lws_gendtls_get_rx(server, buf, sizeof(buf)) < 0)
			goto bail;

		if (move_record(server, client, buf, sizeof(buf), use_udp,
				server_fd, client_fd, &cli_addr, &srv_addr,
				&cli_len))
			goto bail;

		if (lws_gendtls_get_rx(client, buf, sizeof(buf)) < 0)
			goto bail;

		if (lws_gendtls_handshake_done(client) &&
		    lws_gendtls_handshake_done(server))
			break;
	}

	if (use_udp) {
		compatible_close(server_fd);
		compatible_close(client_fd);
	}

	return n < 300 ? 0 : -1;

bail:
	if (server_fd != LWS_SOCK_INVALID)
		compatible_close(server_fd);
	if (client_fd != LWS_SOCK_INVALID)
		compatible_close(client_fd);

	return -1;
}

static int
exchange_appdata(struct lws_gendtls_ctx *client, struct lws_gendtls_ctx *server)
{
	static const uint8_t msg1[] = "first OpenHiTLS DTLS record";
	static const uint8_t msg2[] = "second OpenHiTLS DTLS record";
	uint8_t rec1[2048], rec2[2048], rx[128];
	int n1, n2, n3, r1, r2;

	if (lws_gendtls_put_tx(client, msg1, sizeof(msg1)) ||
	    lws_gendtls_put_tx(client, msg2, sizeof(msg2))) {
		lwsl_err("%s: put_tx failed\n", __func__);
		return -1;
	}

	n1 = lws_gendtls_get_tx(client, rec1, sizeof(rec1));
	n2 = lws_gendtls_get_tx(client, rec2, sizeof(rec2));
	n3 = lws_gendtls_get_tx(client, rec1, sizeof(rec1));
	if (n1 <= 0 || n2 <= 0 || n3) {
		lwsl_err("%s: DTLS record boundary check failed %d/%d/%d\n",
			 __func__, n1, n2, n3);
		return -1;
	}

	if (lws_gendtls_put_rx(server, rec1, (size_t)n1) ||
	    lws_gendtls_put_rx(server, rec2, (size_t)n2))
		return -1;

	r1 = lws_gendtls_get_rx(server, rx, sizeof(rx));
	if (r1 != (int)sizeof(msg1) || memcmp(rx, msg1, sizeof(msg1))) {
		lwsl_err("%s: first record payload mismatch\n", __func__);
		return -1;
	}

	r2 = lws_gendtls_get_rx(server, rx, sizeof(rx));
	if (r2 != (int)sizeof(msg2) || memcmp(rx, msg2, sizeof(msg2))) {
		lwsl_err("%s: second record payload mismatch\n", __func__);
		return -1;
	}

	return 0;
}

static int
check_exporter(struct lws_gendtls_ctx *client, struct lws_gendtls_ctx *server)
{
	static const char label[] = "EXPORTER-lws-openhitls-gendtls";
	uint8_t cexp[32], sexp[32];

	if (lws_gendtls_export_keying_material(client, label,
					       strlen(label), NULL, 0,
					       cexp, sizeof(cexp)) ||
	    lws_gendtls_export_keying_material(server, label,
					       strlen(label), NULL, 0,
					       sexp, sizeof(sexp))) {
		lwsl_err("%s: export_keying_material failed\n", __func__);
		return -1;
	}

	if (memcmp(cexp, sexp, sizeof(cexp))) {
		lwsl_err("%s: client/server exporter mismatch\n", __func__);
		return -1;
	}

	return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_gendtls_ctx client_ctx, server_ctx, srtp_ctx;
	uint8_t *cert_mem = NULL, *key_mem = NULL, empty[8];
	size_t cert_len = 0, key_len = 0;
	struct lws_context *context;
	const char *p;
	int port = 7900, use_udp = 0, ok = 0;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_UDP].sw))
		use_udp = 1;

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw);
	if (p)
		port = atoi(p);

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
	lwsl_user("LWS API Test - openhitls gendtls (UDP: %d)\n", use_udp);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("%s: lws init failed\n", __func__);
		return 1;
	}

	if (load_test_cert_key(&cert_mem, &cert_len, &key_mem, &key_len)) {
		lwsl_err("%s: failed to load test cert/key\n", __func__);
		goto bail_context;
	}

	{
		struct lws_gendtls_creation_info ci = {
			.context = context,
			.mode = LWS_GENDTLS_MODE_CLIENT,
			.mtu = 1200,
			.timeout_ms = 2000,
			.use_srtp = "SRTP_AES128_CM_SHA1_80"
		};

		if (!lws_gendtls_create(&srtp_ctx, &ci)) {
			lwsl_err("%s: OpenHiTLS accepted unsupported DTLS-SRTP\n",
				 __func__);
			lws_gendtls_destroy(&srtp_ctx);
			goto bail_context;
		}
		if (lws_gendtls_get_srtp_profile(&srtp_ctx)) {
			lwsl_err("%s: unexpected SRTP profile\n", __func__);
			goto bail_context;
		}
	}

	{
		struct lws_gendtls_creation_info ci = {
			.context = context,
			.mode = LWS_GENDTLS_MODE_CLIENT,
			.mtu = 1200,
			.timeout_ms = 2000
		};

		if (lws_gendtls_create(&client_ctx, &ci)) {
			lwsl_err("%s: create client failed\n", __func__);
			goto bail_context;
		}

		if (lws_gendtls_get_rx(&client_ctx, empty, sizeof(empty)) < 0) {
			lwsl_err("%s: no-data retry failed\n", __func__);
			goto bail_client;
		}

		ci.mode = LWS_GENDTLS_MODE_SERVER;
		if (lws_gendtls_create(&server_ctx, &ci)) {
			lwsl_err("%s: create server failed\n", __func__);
			goto bail_client;
		}

		if (lws_gendtls_set_cert_mem(&server_ctx, cert_mem, cert_len) ||
		    lws_gendtls_set_key_mem(&server_ctx, key_mem, key_len)) {
			lwsl_err("%s: failed to set server cert/key\n",
				 __func__);
			goto bail_server;
		}

		if (drive_pair(&client_ctx, &server_ctx, use_udp, port)) {
			lwsl_err("%s: DTLS handshake failed\n", __func__);
			goto bail_server;
		}

		if (check_exporter(&client_ctx, &server_ctx) ||
		    exchange_appdata(&client_ctx, &server_ctx))
			goto bail_server;

		if (!lws_gendtls_is_clean(&client_ctx) ||
		    !lws_gendtls_is_clean(&server_ctx)) {
			lwsl_err("%s: contexts not clean after exchange\n",
				 __func__);
			goto bail_server;
		}

		ok = 1;

bail_server:
		lws_gendtls_destroy(&server_ctx);
bail_client:
		lws_gendtls_destroy(&client_ctx);
	}

bail_context:
	free(cert_mem);
	free(key_mem);
	lws_context_destroy(context);

	return lws_cmdline_passfail(argc, argv, !ok);
}
