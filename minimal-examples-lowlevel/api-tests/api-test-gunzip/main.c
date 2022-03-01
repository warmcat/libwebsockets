/*
 * lws-api-test-gunzip
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * tests for LWS_WITH_GZINFLATE (inflator via upng)
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
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int result = 0, more = 1;
	const char *p;
	lws_stateful_ret_t r = LWS_SRET_WANT_INPUT;
	struct inflator_ctx *gunz;
	const uint8_t *outring;
	size_t l = 0, old_op = 0, outringlen, *opl, *cl, pw = 0;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: gunzip\n");

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

	gunz = lws_upng_inflator_create(&outring, &outringlen, &opl, &cl);
	if (!gunz)
		goto bail;

	do {
		uint8_t ib[9];
		const uint8_t *pib = NULL;
		ssize_t s, os;
		size_t ps = 0, part;

		pib = NULL;
		if ((r & LWS_SRET_WANT_INPUT) && more) {
			s = read(fdin, ib, sizeof(ib));

			if (s <= 0) {
				lwsl_err("%s: failed to read: %d (after %lu)\n", __func__, errno, (unsigned long)l);
				more = 0;
			} else {

				pib = ib;
				ps = (size_t)s;
				l += ps;

//				lwsl_hexdump_notice(pib, ps);

				lwsl_info("%s: fetched %u (%u)\n", __func__,
						(unsigned int)s, (unsigned int)l);
			}
		}

		do {
			r = lws_upng_inflate_data(gunz, pib, ps);
			pib = NULL;
			ps = 0;

			// lwsl_notice("r = %d\n", r);

			if (r & LWS_SRET_FATAL) {
				lwsl_err("%s: emit returned FATAL %d\n", __func__, r &0xff);
				result = 1;
				goto bail1;
			}

			if (!more && *opl == old_op) {
				lwsl_notice("%s: seem finished\n", __func__);
				/* no more input possible, and no output came */
				goto bail1;
			}

			os = (ssize_t)((*opl - (size_t)old_op) % outringlen);

			/* if we wrap around the ring, first do the part to the
			 * end of the ring */

			part = (size_t)os;
			if ((*opl % outringlen) < old_op)
				part = outringlen - old_op;

			// lwsl_notice("%s: out %d (%d -> %d)\n", __func__, (int)os, (int)old_op, (int)(old_op + part));

			if (write(fdout, outring + old_op,
#if defined(WIN32)
						(unsigned int)
#endif
						part) < (ssize_t)part) {
				lwsl_err("%s: write %d failed %d\n", __func__,
						(int)os, errno);
				goto bail1;
			}

			/* then do the remainder (if any) from the ring start */

			if ((*opl % outringlen) < old_op)
				if (write(fdout, outring,
	#if defined(WIN32)
							(unsigned int)
	#endif
							*opl % outringlen) < (ssize_t)(*opl % outringlen)) {
					lwsl_err("%s: write %d failed %d\n", __func__,
							(int)os, errno);
					goto bail1;
				}

			old_op = *opl % outringlen;
			*cl = *opl;
			pw = (size_t)(pw + (size_t)os);

			lwsl_debug("%s: wrote %d: r %u (left %u)\n", __func__,
					(int)os, r, (unsigned int)ps);

			if (r == LWS_SRET_OK) {
				lwsl_notice("%s: feels OK %lu\n", __func__, (unsigned long)pw);
				goto bail1;
			}

			if (r & LWS_SRET_WANT_INPUT)
				break;

		} while (ps); /* while any input left */
	} while (1);

bail1:

	lws_upng_inflator_destroy(&gunz);

bail:

	if (fdin >= 0)
		close(fdin);
	if (fdout >= 0 && fdout != 1)
		close(fdout);

	lwsl_user("Completed\n");

	return result;
}
