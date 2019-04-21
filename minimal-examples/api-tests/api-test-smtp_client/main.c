/*
 * lws-api-test-smtp_client
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

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

int main(int argc, const char **argv)
{
	int n = 1, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	struct lws_context *context;
	lws_smtp_client_info_t sci;
	lws_smtp_client_t *smtpc;
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

	/* create the smtp client */

	memset(&sci, 0, sizeof(sci));
	sci.data = NULL /* stmp client specific user data */;
	sci.abs = lws_abstract_get_by_name("raw_skt");
	sci.vh = vh;
	lws_strncpy(sci.ip, "127.0.0.1", sizeof(sci.ip));
	lws_strncpy(sci.helo, "lws-test-client", sizeof(sci.helo));

	smtpc = lws_smtp_client_create(&sci);
	if (!smtpc) {
		lwsl_err("%s: failed to create SMTP client\n", __func__);
		goto bail1;
	}

	/* attach an email to it */

	memset(&email, 0, sizeof(email));
	email.data = NULL /* email specific user data */;
	email.email_from = recip;
	email.email_to = "andy@warmcat.com";
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

	if (lws_smtp_client_add_email(smtpc, &email)) {
		lwsl_err("%s: failed to add email\n", __func__);
		goto bail;
	}

	/* the usual lws event loop */

	while (n >= 0 && !interrupted)
		n = lws_service(context, 1000);

bail:
	lws_smtp_client_destroy(&smtpc);
bail1:
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	lws_context_destroy(context);

	return result;
}
