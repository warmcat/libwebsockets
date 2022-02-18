/*
 * lws-api-test-backtrace
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

int fdin = 0;

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	int result = 1, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, n;
	uint8_t ib[2048], ob[1536], *eib = ib;
	lws_backtrace_info_t si;
	unsigned int m;
	uintptr_t uipt;
	ssize_t s = 0;
	size_t l = 0;
	uint16_t san;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	if ((p = lws_cmdline_option(argc, argv, "--stdin"))) {
		fdin = open(p, LWS_O_RDONLY, 0);
		if (fdin < 0) {
			result = 1;
			lwsl_err("%s: unable to open stdin file\n", __func__);
			goto bail;
		}
	}

	lwsl_user("LWS Compressed Backtrace Decoder\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* confirm operation of lws_sigbits */

	uipt = 0x8000000000000000ull;
	for (n = 64; n; n--) {
		m = lws_sigbits(uipt);
		if (n != (int)m) {
			lwsl_err("a: %d %d\n", n, m);
			goto bail;
		}
		uipt >>= 1;
	}

#if defined(LWS_WITH_ALLOC_METADATA_LWS)
			_lws_alloc_metadata_dump_lws(lws_alloc_metadata_dump_stdout, NULL);
#endif

	if (!fdin) {
		struct timeval timeout;
		fd_set	fds;

		FD_ZERO(&fds);
		FD_SET(0, &fds);

		timeout.tv_sec  = 0;
		timeout.tv_usec = 1000;

		if (select(fdin + 1, &fds, NULL, NULL, &timeout) < 0 ||
		    !FD_ISSET(0, &fds)) {
			result = 1;
			lwsl_err("%s: pass Compressed Backtrace line "
				 "on stdin or use --stdin\n", __func__);
			goto bail;
		}
	}

	while (l != sizeof(ib)) {
		s = read(fdin, ib + l, sizeof(ib) - l);
		if (s <= 0)
			break;
		l = l + (size_t)s;
	}

	if (l < 4)
		goto bail;

	if (ib[0] == '~' && ib[2] == '#') {
		eib += 3;
		l -= 3;
	}

	n = lws_b64_decode_string_len((char *)eib, (int)l, (char *)ob, (int)sizeof(ob));
	if (n <= 0) {
		lwsl_err("%s: invalid base64\n", __func__);
		goto bail;
	}

	lwsl_hexdump_notice(ob, (size_t)n);

	san = (ob[n - 2] << 8) | ob[n - 1];
	if (san != (unsigned int)n) {
		lwsl_err("%s: compressed length wrong\n", __func__);
		goto bail;
	}

	if (lws_alloc_metadata_parse(&si, ob + n)) {
		lwsl_err("%s: compressed parse failed\n", __func__);
		goto bail;
	}

	printf("~b#size: %llu, ", (unsigned long long)si.asize);

	for (n = 0; n < si.sp; n++)
		printf("0x%llx ", (unsigned long long)si.st[n]);
	printf("\n");

	result = 0;

bail:
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	lws_context_destroy(context);

	return result;
}

