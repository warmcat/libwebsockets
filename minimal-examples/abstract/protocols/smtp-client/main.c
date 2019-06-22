/*
 * lws-unit-tests-smtp-client
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

/*
 * from https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol
 */

static lws_expect_t test_send1[] = {
	{
		"220 smtp.example.com ESMTP Postfix",
		34, LWS_AUT_EXPECT_RX
	}, {
		"HELO lws-test-client",
		20, LWS_AUT_EXPECT_TX
	}, {
		"250 smtp.example.com, I am glad to meet you",
		43, LWS_AUT_EXPECT_RX
	}, {
		"MAIL FROM:<noreply@warmcat.com>",
		31, LWS_AUT_EXPECT_TX
	}, {
		"250 Ok",
		6, LWS_AUT_EXPECT_RX
	}, {
		"RCPT TO:andy@warmcat.com",
		24, LWS_AUT_EXPECT_TX
	}, {
		"250 Ok",
		6, LWS_AUT_EXPECT_RX
	}, {
		"DATA",
		4, LWS_AUT_EXPECT_TX
	}, {
		"354 End data with <CR><LF>.<CR><LF>",
		35, LWS_AUT_EXPECT_RX
	}, {
		"From: noreply@example.com\n"
		"To: andy@warmcat.com\n"
		"Subject: Test email for lws smtp-client\n"
		"\n"
		"Hello this was an api test for lws smtp-client\n"
		"\r\n.\r\n",
		27 + 21 + 39 + 1 + 46 + 5, LWS_AUT_EXPECT_TX
	}, {
		"250 Ok: queued as 12345",
		23, LWS_AUT_EXPECT_RX
	}, {
		"QUIT",
		4, LWS_AUT_EXPECT_TX
	}, {
		"221 Bye",
		7, LWS_AUT_EXPECT_RX |
		   LWS_AUT_EXPECT_LOCAL_CLOSE |
		   LWS_AUT_EXPECT_DO_REMOTE_CLOSE |
		   LWS_AUT_EXPECT_TEST_END
	}
};

static lws_expect_test_t tests[] = {
	{ "sending", test_send1 },
	{ }
};

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
 * The test helper calls this on the instance it created to prepare it for
 * the test.
 */

static int
smtp_test_instance_init(lws_abs_t *instance)
{
	lws_smtp_email_t email;

	/* attach an email to it */

	memset(&email, 0, sizeof(email));
	email.data = NULL /* email specific user data */;
	email.email_from = "noreply@warmcat.com";
	email.email_to = "andy@warmcat.com";
	email.payload = malloc(2048);
	if (!email.payload)
		return 1;

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
		return 1;
	}

	return 0;
}

/*
 * We're going to bind to the raw-skt transport, so tell that what we want it
 * to connect to
 */

static const lws_token_map_t smtp_raw_skt_transport_tokens[] = {
 {
	.u = { .value = (const char *)tests },
	.name_index = LTMI_PEER_V_EXPECT_TEST_ARRAY,
 }, {
 }
};

static const lws_token_map_t smtp_protocol_tokens[] = {
 {
	.u = { .value = "lws-test-client" },
	.name_index = LTMI_PSMTP_V_HELO,
	.init = smtp_test_instance_init,
 }, {
 }
};


int main(int argc, const char **argv)
{
	int n = 1, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	struct lws_context *context;
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

	memset(&abs, 0, sizeof(abs));
	abs.vh = vh;

	/* select the protocol and bind its tokens */

	abs.ap = lws_abs_protocol_get_by_name("smtp");
	if (!abs.ap)
		goto bail1;
	abs.ap_tokens = smtp_protocol_tokens;

	/* select the transport and bind its tokens */

	abs.at = lws_abs_transport_get_by_name("unit_tests");
	if (!abs.at)
		goto bail1;

	/*
	 * The transport token we pass here to the test helper is the array
	 * of tests.  The helper will iterate through it instantiating test
	 * connections with one test each.
	 */
	abs.at_tokens = smtp_raw_skt_transport_tokens;

	if (lws_abs_transport_unit_test_helper(&abs)) {
		lwsl_err("%s: failed to create SMTP client\n", __func__);
		goto bail1;
	}


	/* the usual lws event loop */

	while (n >= 0 && !interrupted)
		n = lws_service(context, 1000);

bail:

bail1:
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	lws_context_destroy(context);

	return result;
}
