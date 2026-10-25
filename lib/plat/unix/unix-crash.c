/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * A backtrace on stderr when the process crashes, see
 * READMEs/README.lws_backtrace.md
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "private-lib-core.h"

#include <execinfo.h>
#include <signal.h>

#define LWS_CRASH_BT_DEPTH	64

/* libexecinfo on the BSDs counts frames in size_t, glibc and macOS in int */
#if defined(LWS_HAVE_BACKTRACE_SIZE_T)
typedef size_t lws_bt_count_t;
#else
typedef int lws_bt_count_t;
#endif

static const int crash_sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT };

/*
 * The handler runs on its own stack, so a crash from overflowing the stack
 * can still say where it was
 */
static uint8_t crash_stack[64 * 1024];

/* only async-signal-safe calls from here until the handler returns */

static void
lws_crash_puts(const char *s)
{
	size_t n = strlen(s);
	ssize_t w;

	while (n) {
		w = write(2, s, n);
		if (w <= 0)
			return;
		s += w;
		n -= (size_t)w;
	}
}

static void
lws_crash_handler(int sig)
{
	void *bt[LWS_CRASH_BT_DEPTH];
	char num[12], *p = num + sizeof(num);
	lws_bt_count_t depth;
	int n = sig;

	*--p = '\0';
	do {
		*--p = (char)('0' + (n % 10));
		n /= 10;
	} while (n && p > num);

	lws_crash_puts("\n*** lws: fatal signal ");
	lws_crash_puts(p);
	lws_crash_puts(", backtrace:\n");

	depth = backtrace(bt, (lws_bt_count_t)LWS_ARRAY_SIZE(bt));
	backtrace_symbols_fd(bt, depth, 2);

	lws_crash_puts("*** lws: end of backtrace\n");

	/*
	 * SA_RESETHAND put the default action back, so the process now dies of
	 * the signal as it would have: the parent sees how it died, and the
	 * platform makes its core file or crash report
	 */
	raise(sig);
}

int
lws_crash_backtrace_install(void)
{
	struct sigaction sa, old;
	stack_t ss, oss;
	void *warm;
	size_t n;

	/*
	 * The first backtrace() may load the unwinder, which allocates: get
	 * that done now, not in the handler
	 */
	(void)backtrace(&warm, 1);

	/* leave the thread's alternate signal stack alone if it has one */
	if (!sigaltstack(NULL, &oss) && (oss.ss_flags & SS_DISABLE)) {
		memset(&ss, 0, sizeof(ss));
		ss.ss_sp	= crash_stack;
		ss.ss_size	= sizeof(crash_stack);
		if (sigaltstack(&ss, NULL))
			return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler	= lws_crash_handler;
	sa.sa_flags	= (int)(SA_ONSTACK | SA_RESETHAND);
	sigemptyset(&sa.sa_mask);

	for (n = 0; n < LWS_ARRAY_SIZE(crash_sigs); n++) {
		/* the application's own handling of a signal comes first */
		if (sigaction(crash_sigs[n], NULL, &old) ||
		    (old.sa_flags & SA_SIGINFO) || old.sa_handler != SIG_DFL)
			continue;

		if (sigaction(crash_sigs[n], &sa, NULL))
			return 1;
	}

	return 0;
}
