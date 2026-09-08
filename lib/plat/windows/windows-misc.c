/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 */

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "private-lib-core.h"

/*
 * Normally you don't want this, use lws_sul instead inside the event loop.
 * But sometimes for drivers it makes sense, so there's an internal-only
 * crossplatform api for it.
 */

void
lws_msleep(unsigned int ms)
{
        Sleep(ms);
}

lws_usec_t
lws_now_usecs(void)
{
#ifndef DELTA_EPOCH_IN_MICROSECS
#define DELTA_EPOCH_IN_MICROSECS 11644473600000000ULL
#endif
	FILETIME filetime;
	ULARGE_INTEGER datetime;

#ifdef _WIN32_WCE
	GetCurrentFT(&filetime);
#else
	GetSystemTimeAsFileTime(&filetime);
#endif

	/*
	 * As per Windows documentation for FILETIME, copy the resulting
	 * FILETIME structure to a ULARGE_INTEGER structure using memcpy
	 * (using memcpy instead of direct assignment can prevent alignment
	 * faults on 64-bit Windows).
	 */
	memcpy(&datetime, &filetime, sizeof(datetime));

	/* Windows file times are in 100s of nanoseconds. */
	return (datetime.QuadPart / 10) - DELTA_EPOCH_IN_MICROSECS;
}


#ifdef _WIN32_WCE
time_t time(time_t *t)
{
	time_t ret = lws_now_usecs() / 1000000;

	if(t != NULL)
		*t = ret;

	return ret;
}
#endif

/*
 * BCRYPT_USE_SYSTEM_PREFERRED_RNG, from bcrypt.h... we resolve the entrypoints
 * at runtime rather than link bcrypt.lib / advapi32.lib, so that this works
 * the same on every toolchain and SDK vintage lws is built with.
 */

#define LWS_BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002

typedef LONG (WINAPI *lws_pfn_bcryptgenrandom_t)(void *, unsigned char *,
						 ULONG, ULONG);
typedef BOOLEAN (WINAPI *lws_pfn_rtlgenrandom_t)(void *, ULONG);

static lws_pfn_bcryptgenrandom_t	lws_pfn_bcryptgenrandom;
static lws_pfn_rtlgenrandom_t		lws_pfn_rtlgenrandom;

/* 0 = not tried yet, 1 = resolution in progress, 2 = resolved */
static volatile LONG			lws_random_resolved;

static void
lws_plat_random_resolve(void)
{
	HMODULE h;

	if (lws_random_resolved == 2)
		return;

	if (InterlockedCompareExchange(&lws_random_resolved, 1, 0)) {
		/* someone else is doing it... wait for him to finish */
		while (lws_random_resolved != 2)
			Sleep(0);

		return;
	}

	h = LoadLibraryA("bcrypt.dll");
	if (h)
		lws_pfn_bcryptgenrandom = (lws_pfn_bcryptgenrandom_t)
					GetProcAddress(h, "BCryptGenRandom");

	if (!lws_pfn_bcryptgenrandom) {
		/* Vista and before... RtlGenRandom, aka SystemFunction036 */

		h = LoadLibraryA("advapi32.dll");
		if (h)
			lws_pfn_rtlgenrandom = (lws_pfn_rtlgenrandom_t)
					GetProcAddress(h, "SystemFunction036");
	}

	InterlockedExchange(&lws_random_resolved, 2);
}

size_t
lws_get_random(struct lws_context *context, void *buf, size_t len)
{
	uint8_t *p = (uint8_t *)buf;
	size_t done = 0;

	/*
	 * Callers are entitled to believe that a return of len means len good
	 * random bytes, and use the result directly as key, IV or nonce
	 * material... so on any failure, destroy whatever we produced and
	 * return 0 rather than hand out something predictable.
	 */

	lws_plat_random_resolve();

	while (done < len) {
		ULONG chunk = (ULONG)((len - done > 0x10000000u) ?
					0x10000000u : len - done);

		if (lws_pfn_bcryptgenrandom) {
			if (lws_pfn_bcryptgenrandom(NULL, p + done, chunk,
					LWS_BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
				goto fail;
		} else {
			if (!lws_pfn_rtlgenrandom ||
			    !lws_pfn_rtlgenrandom(p + done, chunk))
				goto fail;
		}

		done += chunk;
	}

	return done;

fail:
	lwsl_err("%s: no system entropy source\n", __func__);

	lws_explicit_bzero(buf, len);

	return 0;
}


void
lwsl_emit_syslog(int level, const char *line)
{
	lwsl_emit_stderr(level, line);
}


int kill(int pid, int sig)
{
	lwsl_err("Sorry Windows doesn't support kill().");
	exit(0);
}

int fork(void)
{
	lwsl_err("Sorry Windows doesn't support fork().");
	exit(0);
}


int
lws_plat_recommended_rsa_bits(void)
{
	return 4096;
}



