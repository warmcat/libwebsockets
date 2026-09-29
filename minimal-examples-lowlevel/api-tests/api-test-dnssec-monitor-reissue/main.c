/*
 * lws-api-test-dnssec-monitor-reissue
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Exercises the dnssec-monitor proxy's "Force cert reissue" handling
 * (monitor-acme.c), which the proxy answers itself by asking the ACME
 * client over SMD rather than forwarding it to the root process:
 *
 *  - any other request is left for the root process, whatever it carries
 *  - a valid request for one cert, with its members in either order, is
 *    answered ok and reaches an LWSSMDCL_CERTS subscriber as the documented
 *    message
 *  - a missing, malformed or non-DNS-name domain or fqdn, or an fqdn not
 *    inside the domain, is answered with an error and sends nothing, so
 *    nothing from the browser can shape the SMD JSON or reach past one cert
 *  - an answer that would not fit whole in the reply space is not sent,
 *    and then the ACME client is not asked either
 */

#include <libwebsockets.h>

#include <string.h>

#include "private.h"

static char smd_rx[256];
static int smd_count, timed_out;
static lws_sorted_usec_list_t sul_timeout;
static struct lws_context *cx;

static int
t_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("%s: FAILED: %s\n", __func__, what);

		return 1;
	}

	return 0;
}

static int
smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp,
       void *buf, size_t len)
{
	if (len >= sizeof(smd_rx))
		len = sizeof(smd_rx) - 1;
	memcpy(smd_rx, buf, len);
	smd_rx[len] = '\0';
	smd_count++;
	lws_cancel_service(cx);

	return 0;
}

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	timed_out = 1;
	lws_cancel_service(cx);
}

/*
 * lws_service() does not honour its timeout: bound the wait for the SMD
 * delivery with a sul, whose callback has to wake the loop itself
 */

static void
t_wait_smd(int want, lws_usec_t us)
{
	timed_out = 0;
	lws_sul_schedule(cx, 0, &sul_timeout, timeout_cb, us);
	while (smd_count < want && !timed_out)
		if (lws_service(cx, 0) < 0)
			break;
	lws_sul_cancel(&sul_timeout);
}

static int
t_req(const char *req, char *reply, size_t reply_len)
{
	reply[0] = '\0';

	return monitor_ui_local_req(cx, req, strlen(req), reply, reply_len);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_smd_peer *peer;
	char reply[256], tiny[16];
	int fails = 0, n;

	/* no defaults: nothing here may go out on the network */
	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;

	lwsl_user("LWS API selftest: dnssec-monitor force cert reissue\n");

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	peer = lws_smd_register(cx, NULL, 0, LWSSMDCL_CERTS, smd_cb);
	fails += t_expect(!!peer, "smd register");

	/* not ours: left for the root process, nothing sent */

	fails += t_expect(t_req("{\"req\":\"get_domains\"}",
				reply, sizeof(reply)) == -1 && !reply[0],
			  "other req goes to root");
	fails += t_expect(t_req("{\"req\":\"update_zone\",\"domain\":"
				"\"example.com\",\"zone\":\"$ORIGIN x.\\n\"}",
				reply, sizeof(reply)) == -1,
			  "other req with a domain goes to root");
	fails += t_expect(t_req("{\"domain\":\"example.com\"}",
				reply, sizeof(reply)) == -1,
			  "no req goes to root");

	/* a valid request names one cert, inside its domain */

	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":"
		  "\"selfdns.org\",\"fqdn\":\"www.selfdns.org\"}",
		  reply, sizeof(reply));
	fails += t_expect(n > 0 && (size_t)n == strlen(reply) &&
			  !strcmp(reply, "{\"req\":\"force_cert_reissue\","
				  "\"status\":\"ok\",\"domain\":\"selfdns.org\","
				  "\"fqdn\":\"www.selfdns.org\"}\n"),
			  "valid request answered ok");
	t_wait_smd(1, 3 * LWS_US_PER_SEC);
	fails += t_expect(smd_count == 1 &&
			  !strcmp(smd_rx, "{\"acme\":\"force-reissue\","
				  "\"domain\":\"selfdns.org\","
				  "\"common-name\":\"www.selfdns.org\"}"),
			  "ACME client asked over SMD");

	n = t_req("{\"fqdn\":\"*.Sub-1.example.com\",\"domain\":"
		  "\"Sub-1.example.com\",\"req\":\"force_cert_reissue\"}",
		  reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"status\":\"ok\""),
			  "members in the other order, wildcard cert");
	t_wait_smd(2, 3 * LWS_US_PER_SEC);
	fails += t_expect(smd_count == 2 &&
			  !strcmp(smd_rx, "{\"acme\":\"force-reissue\","
				  "\"domain\":\"Sub-1.example.com\","
				  "\"common-name\":\"*.Sub-1.example.com\"}"),
			  "second request reaches SMD");

	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":\"x.org\","
		  "\"fqdn\":\"x.org\"}", reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"status\":\"ok\""),
			  "cert for the domain itself");
	t_wait_smd(3, 3 * LWS_US_PER_SEC);
	fails += t_expect(smd_count == 3, "third request reaches SMD");

	/* refused: answered with an error, nothing sent */

	n = t_req("{\"req\":\"force_cert_reissue\",\"fqdn\":\"x.org\"}",
		  reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"msg\":\"Missing domain\""),
			  "missing domain");
	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":\".x.org\","
		  "\"fqdn\":\"a.x.org\"}", reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"msg\":\"Missing domain\""),
			  "leading dot");
	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":\"x.org\"}",
		  reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"msg\":\"Missing fqdn\""),
			  "missing fqdn: never the whole domain");
	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":"
		  "\"a\\\",\\\"x\\\":\\\"b.org\",\"fqdn\":\"b.org\"}",
		  reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"msg\":\"Invalid domain\""),
			  "quote injection in domain refused");
	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":\"*.x.org\","
		  "\"fqdn\":\"*.x.org\"}", reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"msg\":\"Invalid domain\""),
			  "wildcard domain refused");
	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":\"b.org\","
		  "\"fqdn\":\"a\\\",\\\"x\\\":\\\"b.org\"}",
		  reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"msg\":\"Invalid fqdn\""),
			  "quote injection in fqdn refused");
	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":\"b.org\","
		  "\"fqdn\":\"a\\nb.org\"}", reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"msg\":\"Invalid fqdn\""),
			  "newline refused");
	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":\"x.org\","
		  "\"fqdn\":\"www.y.org\"}", reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"msg\":\"fqdn not in domain\""),
			  "fqdn of another domain");
	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":\"x.org\","
		  "\"fqdn\":\"evilx.org\"}", reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"msg\":\"fqdn not in domain\""),
			  "fqdn only sharing a suffix");
	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":\"x.org\"",
		  reply, sizeof(reply));
	fails += t_expect(n > 0 && strstr(reply, "\"msg\":\"Malformed request\""),
			  "truncated request");

	/* no room for the whole answer: nothing queued */

	n = t_req("{\"req\":\"force_cert_reissue\",\"domain\":\"x.org\","
		  "\"fqdn\":\"x.org\"}", tiny, sizeof(tiny));
	fails += t_expect(n == 0, "answer that doesn't fit is not sent");

	/* only the three answered valid requests went out */
	t_wait_smd(4, LWS_US_PER_SEC);
	fails += t_expect(smd_count == 3, "no SMD for refused requests");

	lws_smd_unregister(peer);
	lws_context_destroy(cx);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
