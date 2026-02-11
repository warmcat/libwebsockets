/*
 * lws-api-test-gendls
 *
 * Written in 2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#if defined(WIN32) || defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#define compatible_close closesocket
#define lws_usleep(x) Sleep((x) / 1000)
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define compatible_close close
#define lws_usleep(x) usleep(x)
#endif
#include <errno.h>

/*
 * We need a minimal context for the example
 */

static const struct lws_context_creation_info info = {
	.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT,
};

;

int read_file_into_mem(const char *path, uint8_t **buf, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize < 0) { fclose(f); return -1; }
    *len = (size_t)fsize;
    fseek(f, 0, SEEK_SET);
    *buf = malloc(*len + 1);
    if (!*buf) { fclose(f); return -1; }
    fread(*buf, 1, *len, f);
    (*buf)[*len] = 0;
    *len = (size_t)fsize + 1;
    fclose(f);
    return 0;
}

lws_sockfd_type udp_socket(int port) {
    lws_sockfd_type fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sin;
    if (fd == LWS_SOCK_INVALID) return LWS_SOCK_INVALID;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)port);
    sin.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        compatible_close(fd);
        return LWS_SOCK_INVALID;
    }
    return fd;
}

int main(int argc, const char **argv)
{
	struct lws_context *context;
	struct lws_gendtls_ctx client_ctx, server_ctx;
	uint8_t buf[2048], *cert_mem = NULL, *key_mem = NULL;
	size_t cert_len = 0, key_len = 0;
    int n, m, ok = 0;
    int use_udp = 0;

    if (lws_cmdline_option(argc, (const char **)argv, "--udp")) {
        use_udp = 1;
    }

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
	lwsl_user("LWS API Test - gendtls (UDP: %d)\n", use_udp);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

    /* Load certs from installed share dir or local build dir */
    {
        const char *paths[] = {
            "./",                   /* User requested root check */
            LWS_INSTALL_DATADIR "/libwebsockets-test-server/",
            "",                     /* CTest / build dir */
            "../",                  /* Linux manual from build/bin */
            "../../",               /* Windows manual from build/bin/Debug */
            "bin/share/libwebsockets-test-server/", /* Windows CTEST */
            "../../share/libwebsockets-test-server/", /* Windows manual alternate */
            "../../../share/libwebsockets-test-server/" /* Original */
        };
        int i, loaded = 0;
        char cert_path[256], key_path[256];

        for (i = 0; i < (int)LWS_ARRAY_SIZE(paths); i++) {
            lws_snprintf(cert_path, sizeof(cert_path), "%slibwebsockets-test-server.pem", paths[i]);
            lws_snprintf(key_path, sizeof(key_path), "%slibwebsockets-test-server.key.pem", paths[i]);

            if (!read_file_into_mem(cert_path, &cert_mem, &cert_len) &&
                !read_file_into_mem(key_path, &key_mem, &key_len)) {
                lwsl_notice("Loaded certs from %s\n", paths[i]);
                loaded = 1;
                break;
            }
            if (cert_mem) { free(cert_mem); cert_mem = NULL; cert_len = 0; }
            if (key_mem) { free(key_mem); key_mem = NULL; key_len = 0; }
            lwsl_info("Failed to load certs from %s\n", paths[i]);
        }

        if (!loaded) {
            lwsl_err("Failed to load test certs from file\n");
            for (i = 0; i < (int)LWS_ARRAY_SIZE(paths); i++) {
                lwsl_err("  Tried: %slibwebsockets-test-server.pem\n", paths[i]);
            }
            return 1;
        }
    }

	struct lws_gendtls_creation_info inf = {
		.context = context,
		.mode = LWS_GENDTLS_MODE_CLIENT,
		.mtu = 1200,
		.timeout_ms = 2000
	};

	if (lws_gendtls_create(&client_ctx, &inf)) {
		lwsl_err("create client failed\n");
		goto bail;
	}

	inf.mode = LWS_GENDTLS_MODE_SERVER;
	if (lws_gendtls_create(&server_ctx, &inf)) {
		lwsl_err("create server failed\n");
		goto bail_client;
	}

    if (lws_gendtls_set_cert_mem(&server_ctx, cert_mem, cert_len) ||
        lws_gendtls_set_key_mem(&server_ctx, key_mem, key_len)) {
        lwsl_err("Failed to set server cert/key\n");
        goto bail_server;
    }

    lws_sockfd_type client_fd = LWS_SOCK_INVALID, server_fd = LWS_SOCK_INVALID;
    struct sockaddr_in srv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int port = 7890;
    const char *p;

    if ((p = lws_cmdline_option(argc, (const char **)argv, "--port"))) {
        port = atoi(p);
    }

    if (use_udp) {
        server_fd = udp_socket(port);
        client_fd = udp_socket(0);
        if (server_fd == LWS_SOCK_INVALID || client_fd == LWS_SOCK_INVALID) {
            lwsl_err("Failed to create UDP sockets on port %d\n", port);
            goto bail_server;
        }
        memset(&srv_addr, 0, sizeof(srv_addr));
        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);
    }

#if defined(LWS_WITH_SCHANNEL)
    if (use_udp) {
        lws_gendtls_schannel_set_client_addr(&client_ctx, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    } else {
        struct sockaddr_in dummy;
        memset(&dummy, 0, sizeof(dummy));
        dummy.sin_family = AF_INET;
        dummy.sin_port = htons(12345);
        inet_pton(AF_INET, "127.0.0.1", &dummy.sin_addr);
        lws_gendtls_schannel_set_client_addr(&client_ctx, (struct sockaddr *)&dummy, sizeof(dummy));
    }
#endif

    /* Loopback Handshake */
    lwsl_user("Starting Handshake...\n");
    int loop = 0;
    while (loop++ < 200) {
        lws_usleep(10000); /* 10ms wait */

        /* Client -> Server */
        n = lws_gendtls_get_tx(&client_ctx, buf, sizeof(buf));
        if (n > 0) {
            // lwsl_user("Client -> Server (%d bytes)\n", n);
            if (use_udp) {
                sendto(client_fd, buf, (size_t)n, 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
                ssize_t r = recvfrom(server_fd, buf, sizeof(buf), 0, (struct sockaddr *)&cli_addr, &cli_len);
                if (r > 0) {
#if defined(LWS_WITH_SCHANNEL)
                    lws_gendtls_schannel_set_client_addr(&server_ctx, (struct sockaddr *)&cli_addr, cli_len);
#endif
                    lws_gendtls_put_rx(&server_ctx, buf, (size_t)r);
                }
            } else {
#if defined(LWS_WITH_SCHANNEL)
                /* Create a dummy valid address for loopback non-UDP since SChannel STRICTLY needs one */
                struct sockaddr_in dummy;
                memset(&dummy, 0, sizeof(dummy));
                dummy.sin_family = AF_INET;
                dummy.sin_port = htons(12345);
                inet_pton(AF_INET, "127.0.0.1", &dummy.sin_addr);
                lws_gendtls_schannel_set_client_addr(&server_ctx, (struct sockaddr *)&dummy, sizeof(dummy));
#endif
                lws_gendtls_put_rx(&server_ctx, buf, (size_t)n);
            }
        }

        /* Drive Server State */
        lws_gendtls_get_rx(&server_ctx, buf, sizeof(buf));

        /* Server -> Client */
        n = lws_gendtls_get_tx(&server_ctx, buf, sizeof(buf));
        if (n > 0) {
            // lwsl_user("Server -> Client (%d bytes)\n", n);
           if (use_udp) {
                sendto(server_fd, buf, (size_t)n, 0, (struct sockaddr *)&cli_addr, cli_len);
                ssize_t r = recvfrom(client_fd, buf, sizeof(buf), 0, NULL, NULL);
                if (r > 0) lws_gendtls_put_rx(&client_ctx, buf, (size_t)r);
            } else {
                lws_gendtls_put_rx(&client_ctx, buf, (size_t)n);
            }
        }

        /* Drive Client State */
        lws_gendtls_get_rx(&client_ctx, buf, sizeof(buf));

		if (lws_gendtls_handshake_done(&client_ctx) &&
		    lws_gendtls_handshake_done(&server_ctx) &&
		    lws_gendtls_is_clean(&client_ctx) &&
		    lws_gendtls_is_clean(&server_ctx))
				break;
    }

    /* Generate Encrypted Payload using lws_xos */
    lwsl_user("Generating payload with lws_xos...\n");
    struct lws_xos xos;
    lws_xos_init(&xos, 12345);
    uint8_t payload[1024];
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)lws_xos(&xos);
    }

    lwsl_user("Sending payload...\n");
    lws_gendtls_put_tx(&client_ctx, payload, sizeof(payload));

    /* Flush TX from Client */
    n = lws_gendtls_get_tx(&client_ctx, buf, sizeof(buf));
    if (n <= 0) {
        lwsl_err("Failed to get encrypted payload from client\n");
        goto bail_server;
    }

    lwsl_user("Encrypted payload (%d bytes)\n", n);

    if (use_udp) {
         sendto(client_fd, buf, (size_t)n, 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
         ssize_t r = recvfrom(server_fd, buf, sizeof(buf), 0, (struct sockaddr *)&cli_addr, &cli_len);
         if (r > 0) {
#if defined(LWS_WITH_SCHANNEL)
             lws_gendtls_schannel_set_client_addr(&server_ctx, (struct sockaddr *)&cli_addr, cli_len);
#endif
             lws_gendtls_put_rx(&server_ctx, buf, (size_t)r);
         }
    } else {
#if defined(LWS_WITH_SCHANNEL)
         struct sockaddr_in dummy;
         memset(&dummy, 0, sizeof(dummy));
         dummy.sin_family = AF_INET;
         dummy.sin_port = htons(12345);
         inet_pton(AF_INET, "127.0.0.1", &dummy.sin_addr);
         lws_gendtls_schannel_set_client_addr(&server_ctx, (struct sockaddr *)&dummy, sizeof(dummy));
#endif
         lws_gendtls_put_rx(&server_ctx, buf, (size_t)n);
    }

    uint8_t rx[2048];
    m = lws_gendtls_get_rx(&server_ctx, rx, sizeof(rx));
    if (m > 0) {
        lwsl_user("Server received: %d bytes\n", m);
        if (m == (int)sizeof(payload) && memcmp(rx, payload, sizeof(payload)) == 0) {
            lwsl_user("SUCCESS: Payload match\n");
            ok = 1;
        } else {
            lwsl_err("FAILURE: Payload mismatch\n");
            lwsl_hexdump(rx, (size_t)m);
        }
    } else {
        lwsl_err("Server failed to decrypt or no data\n");
    }

bail_server:
	lws_gendtls_destroy(&server_ctx);
    if (server_fd != LWS_SOCK_INVALID) compatible_close(server_fd);
bail_client:
	lws_gendtls_destroy(&client_ctx);
    if (client_fd != LWS_SOCK_INVALID) compatible_close(client_fd);
bail:
    if (cert_mem) free(cert_mem);
    if (key_mem) free(key_mem);
	lws_context_destroy(context);

	return lws_cmdline_passfail(argc, argv, !ok);
}
