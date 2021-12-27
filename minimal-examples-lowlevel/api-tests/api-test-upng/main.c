/*
 * lws-api-test-upng
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

int fdin = 0, fdout = 1;

int
main(int argc, const char **argv)
{
	int result = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	lws_stateful_ret_t r = LWS_SRET_WANT_INPUT;
	const char *p;
	lws_upng_t *u;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS UPNG test tool\n");

	if ((p = lws_cmdline_option(argc, argv, "--stdin"))) {
		fdin = open(p, LWS_O_RDONLY, 0);
		if (fdin < 0) {
			result = 1;
			lwsl_err("%s: unable to open stdin file\n", __func__);
			goto bail;
		}
	}

	if ((p = lws_cmdline_option(argc, argv, "--stdout"))) {
		fdout = open(p, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0600);
		if (fdout < 0) {
			result = 1;
			lwsl_err("%s: unable to open stdout file\n", __func__);
			goto bail;
		}
	}

	if (!fdin) {
		struct timeval	timeout;
		fd_set	fds;

		FD_ZERO(&fds);
		FD_SET(0, &fds);

		timeout.tv_sec  = 0;
		timeout.tv_usec = 1000;

		if (select(fdin + 1, &fds, NULL, NULL, &timeout) < 0 ||
		    !FD_ISSET(0, &fds)) {
			result = 1;
			lwsl_err("%s: pass PNG "
				 "on stdin or use --stdin\n", __func__);
			goto bail;
		}
	}


	u = lws_upng_new();
	if (!u) {
		lwsl_err("%s: failed to allocate\n", __func__);
		goto bail;
	}

	do {
		const uint8_t *pix;
		uint8_t ib[256];
		const uint8_t *pib = (const uint8_t *)ib;
		ssize_t s, os;
		size_t ps;

		if (r == LWS_SRET_WANT_INPUT) {
			s = read(fdin, ib, sizeof(ib));

			if (s <= 0) {
				lwsl_err("%s: failed to read: %d\n", __func__, errno);
				goto bail1;
			}

			ps = (size_t)s;

			// lwsl_notice("%s: fetched %d\n", __func__, (int)s);
		}

		do {
			r = lws_upng_emit_next_line(u, &pix, &pib, &ps, 0);
			if (r == LWS_SRET_WANT_INPUT)
				break;

			if (r > LWS_SRET_FATAL) {
				lwsl_err("%s: emit returned FATAL %d\n", __func__, r &0xff);
				result = 1;
				goto bail1;
			}

			if (!pix)
				goto bail1;

			os = (ssize_t)(lws_upng_get_width(u) * (lws_upng_get_pixelsize(u) / 8));

			if (write(fdout, pix, 
#if defined(WIN32)
						(unsigned int)
#endif
						(size_t)os) < os) {
				lwsl_err("%s: write %d failed %d\n", __func__, (int)os, errno);
				goto bail1;
			}

			lwsl_notice("%s: wrote %d\n", __func__, (int)os);
		} while (ps);

	} while (1);

bail1:
	if (fdin)
		close(fdin);
	if (fdout != 1)
		close(fdout);

	lws_upng_free(&u);

bail:
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
