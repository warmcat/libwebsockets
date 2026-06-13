#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted;

void sigint_handler(int sig)
{
	interrupted = 1;
}

extern const struct lws_protocols lws_auth_dns_protocols[];

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int n = 0;
	const char *p;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	info.port = 5353;
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		{
			int __pt = atoi(p);
			if (__pt < 0 || __pt > 65535) {
				lwsl_err("Port %d is outside valid 16-bit range\n", __pt);
				return 1;
			}
			info.port = __pt;
		}

	const struct lws_protocols my_protocols[] = {
		lws_auth_dns_protocols[0],
		{ NULL, NULL, 0, 0, 0, NULL, 0 }
	};
	info.protocols = my_protocols;
	info.options = LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "protocol-lws-auth-dns";

	const char *z = "../minimal-examples-lowlevel/api-tests/api-test-dns-server/zones-api-test/";
	if ((p = lws_cmdline_option(argc, argv, "-z")))
		z = p;

	const struct lws_protocol_vhost_options pvo1 = {
		NULL, NULL, "zone-dir", z
	};
	const struct lws_protocol_vhost_options pvo = {
		NULL, &pvo1, "protocol-lws-auth-dns", ""
	};
	info.pvo = &pvo;

	lwsl_user("LWS mock DNS server | port %d\n", info.port);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
}
