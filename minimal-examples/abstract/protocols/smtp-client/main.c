/*
 * lws-api-test-smtp_client
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

#include <signal.h>

static int interrupted, result = 1;
static const char *recip;

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

static int
email_sent_or_failed(struct lws_smtp_email *email, void *buf, size_t len)
{
	/* you could examine email->data here */
	if (buf)
		lwsl_notice("%s: %.*s\n", __func__, (int)len, (const char *)buf);
	else
		lwsl_notice("%s:\n", __func__);

	/* destroy any allocations in email */

	free((char *)email->payload);

	result = 0;
	interrupted = 1;

	return 0;
}

/*
 * We're going to bind to the raw-skt transport, so tell that what we want it
 * to connect to
 */

static const lws_token_map_t smtp_raw_skt_transport_tokens[] = {
 {
	.u = { .value = "127.0.0.1" },
	.name_index = LTMI_PEER_V_DNS_ADDRESS,
 }, {
	.u = { .lvalue = 25 },
	.name_index = LTMI_PEER_LV_PORT,
 }, {
 }
};

static const lws_token_map_t smtp_protocol_tokens[] = {
 {
	.u = { .value = "lws-test-client" },
	.name_index = LTMI_PSMTP_V_HELO,
 }, {
 }
};


int main(int argc, const char **argv)
{
	int n = 1, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	struct lws_context *context;
	lws_abs_t abs, *instance;
	lws_smtp_email_t email;
	struct lws_vhost *vh;
	const char *p;

	/* the normal lws init */

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	p = lws_cmdline_option(argc, argv, "-r");
	if (!p) {
		lwsl_err("-r <recipient email> is required\n");
		return 1;
	}
	recip = p;

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: SMTP client\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create first vhost\n");
		goto bail1;
	}

	/*
	 * create an smtp client that's hooked up to real sockets
	 */

	memset(&abs, 0, sizeof(abs));
	abs.vh = vh;

	/* select the protocol and bind its tokens */

	abs.ap = lws_abs_protocol_get_by_name("smtp");
	if (!abs.ap)
		goto bail1;
	abs.ap_tokens = smtp_protocol_tokens;

	/* select the transport and bind its tokens */

	abs.at = lws_abs_transport_get_by_name("raw_skt");
	if (!abs.at)
		goto bail1;
	abs.at_tokens = smtp_raw_skt_transport_tokens;

	instance = lws_abs_bind_and_create_instance(&abs);
	if (!instance) {
		lwsl_err("%s: failed to create SMTP client\n", __func__);
		goto bail1;
	}

	/* attach an email to it */

	memset(&email, 0, sizeof(email));
	email.data = NULL /* email specific user data */;
	email.email_from = "andy@warmcat.com";
	email.email_to = recip;
	email.payload = malloc(2048);
	if (!email.payload) {
		goto bail1;
	}

	lws_snprintf((char *)email.payload, 2048,
			"From: noreply@example.com\n"
			"To: %s\n"
			"Subject: Test email for lws smtp-client\n"
			"\n"
			"Hello this was an api test for lws smtp-client\n"
			"\r\n.\r\n", recip);
	email.done = email_sent_or_failed;

	if (lws_smtp_client_add_email(instance, &email)) {
		lwsl_err("%s: failed to add email\n", __func__);
		goto bail;
	}

	/* the usual lws event loop */

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

bail:

bail1:
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	lws_context_destroy(context);

	return result;
}
