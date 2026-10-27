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
 *
 * A fault, eg, an access violation, is a structured exception, which a CRT
 * signal handler never sees: it reaches us at the unhandled exception filter.
 * abort(), eg, from a failed assert(), raises SIGABRT, and the Debug CRT then
 * exits with code 3 saying nothing when there is no console.
 */

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "private-lib-core.h"

#include <dbghelp.h>
#include <signal.h>
#include <stdio.h>

#define LWS_CRASH_BT_DEPTH	62
#define LWS_CRASH_SYM_LEN	255

/* the filter there was before ours, which gets the exception first */
static LPTOP_LEVEL_EXCEPTION_FILTER lws_crash_prev_filter;

/*
 * Unlike the unix signal handler, a filter runs as ordinary code, so it can
 * use stdio and DbgHelp.  DbgHelp names each frame from the module's .pdb,
 * with its source line, where it can find one.
 */

static void
lws_crash_print(const char *what)
{
	/* SYMBOL_INFO ends with the start of the name, room for it follows */
	struct {
		SYMBOL_INFO	si;
		char		name[LWS_CRASH_SYM_LEN + 1];
	} s;
	SYMBOL_INFO *sym = &s.si;
	HANDLE proc = GetCurrentProcess();
	void *frames[LWS_CRASH_BT_DEPTH];
	IMAGEHLP_LINE64 line;
	DWORD64 disp64, a;
	DWORD disp;
	WORD n, i;

	fprintf(stderr, "\n*** lws: fatal %s, backtrace:\n", what);

	SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME |
		      SYMOPT_DEFERRED_LOADS);
	/* fails if the application initialised DbgHelp itself: that's fine */
	SymInitialize(proc, NULL, TRUE);

	n = CaptureStackBackTrace(0, LWS_CRASH_BT_DEPTH, frames, NULL);
	for (i = 0; i < n; i++) {
		a = (DWORD64)(uintptr_t)frames[i];

		memset(&s, 0, sizeof(s));
		sym->SizeOfStruct	= (ULONG)sizeof(SYMBOL_INFO);
		sym->MaxNameLen		= LWS_CRASH_SYM_LEN;
		disp64			= 0;

		if (!SymFromAddr(proc, a, &disp64, sym)) {
			fprintf(stderr, "  #%u 0x%llx\n", (unsigned int)i,
				(unsigned long long)a);
			continue;
		}

		memset(&line, 0, sizeof(line));
		line.SizeOfStruct	= (DWORD)sizeof(line);
		disp			= 0;

		if (SymGetLineFromAddr64(proc, a, &disp, &line))
			fprintf(stderr, "  #%u %s+0x%llx (%s:%lu)\n",
				(unsigned int)i, sym->Name,
				(unsigned long long)disp64, line.FileName,
				(unsigned long)line.LineNumber);
		else
			fprintf(stderr, "  #%u %s+0x%llx\n", (unsigned int)i,
				sym->Name, (unsigned long long)disp64);
	}

	fprintf(stderr, "*** lws: end of backtrace\n");
	fflush(stderr);
}

static LONG WINAPI
lws_crash_filter(EXCEPTION_POINTERS *ep)
{
	char what[40];
	LONG r;

	/*
	 * Whoever was there before us decides first.  The MSVC startup code
	 * always is, so we can't tell an application's filter by there being
	 * one: the CRT's own only takes C++ exceptions, which it terminate()s
	 * and we see as SIGABRT, and passes the rest on
	 */
	if (lws_crash_prev_filter) {
		r = lws_crash_prev_filter(ep);
		if (r != EXCEPTION_CONTINUE_SEARCH)
			return r;
	}

	lws_snprintf(what, sizeof(what), "exception 0x%08lx",
		     (unsigned long)ep->ExceptionRecord->ExceptionCode);
	lws_crash_print(what);

	/*
	 * The default handling goes on: Windows Error Reporting, and the
	 * process exits with the exception code, as it would have
	 */
	return EXCEPTION_CONTINUE_SEARCH;
}

static void __cdecl
lws_crash_sigabrt(int sig)
{
	char what[24];

	lws_snprintf(what, sizeof(what), "signal %d", sig);
	lws_crash_print(what);

	/* let the default action finish it, exit code 3 for abort() */
	signal(sig, SIG_DFL);
	raise(sig);
}

int
lws_crash_backtrace_install(void)
{
	LPTOP_LEVEL_EXCEPTION_FILTER prev;
	void (__cdecl *old)(int);

	/* lws_crash_filter() calls any filter that was there before it */
	prev = SetUnhandledExceptionFilter(lws_crash_filter);
	if (prev != lws_crash_filter)
		lws_crash_prev_filter = prev;

	old = signal(SIGABRT, lws_crash_sigabrt);
	if (old == SIG_ERR)
		return 1;
	if (old != SIG_DFL && old != lws_crash_sigabrt)
		signal(SIGABRT, old);

	return 0;
}
