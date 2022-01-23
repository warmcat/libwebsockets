/*
 * lws-api-test-picojpeg
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
	lws_jpeg_t *j;
	size_t l = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS JPEG test tool\n");

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
		struct timeval timeout;
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


	j = lws_jpeg_new();
	if (!j) {
		lwsl_err("%s: failed to allocate\n", __func__);
		goto bail;
	}

	do {
		uint8_t ib[128];
		const uint8_t *pib = (const uint8_t *)ib;
		const uint8_t *pix = NULL;
		ssize_t s, os;
		size_t ps = 0;

		if (r == LWS_SRET_WANT_INPUT) {
			s = read(fdin, ib, sizeof(ib));

			if (s <= 0) {
				lwsl_err("%s: failed to read: %d\n", __func__, errno);
				goto bail1;
			}

			ps = (size_t)s;
			l += ps;

			lwsl_info("%s: fetched %u (%u)\n", __func__,
					(unsigned int)s, (unsigned int)l);
		}

		do {
			r = lws_jpeg_emit_next_line(j, &pix, &pib, &ps, 0);
			if (r == LWS_SRET_WANT_INPUT)
				break;

			if (r >= LWS_SRET_FATAL) {
				lwsl_notice("%s: emit returned FATAL\n", __func__);
				result = 1;
				goto bail1;
			}

			if (!pix)
				goto bail1;

			os = (ssize_t)(lws_jpeg_get_width(j) * (lws_jpeg_get_pixelsize(j) / 8));

			if (write(fdout, pix, 
#if defined(WIN32)
						(unsigned int)
#endif
						(size_t)os) < os) {
				lwsl_err("%s: write %d failed %d\n", __func__,
						(int)os, errno);
				goto bail1;
			}

			lwsl_info("%s: wrote %d: r %u (left %u)\n", __func__,
					(int)os, r, (unsigned int)ps);

			if (r == LWS_SRET_OK)
				goto bail1;

		} while (ps); /* while any input left */

	} while (1);

bail1:
	if (fdin)
		close(fdin);
	if (fdout != 1)
		close(fdout);

	lws_jpeg_free(&j);

bail:
	lwsl_user("Completed: %s (read %u)\n", result ? "FAIL" : "PASS",
							(unsigned int)l);

	return result;
}
