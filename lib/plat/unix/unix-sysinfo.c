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
 */

#include "private-lib-core.h"
#include "private-lib-system-sysinfo.h"

#include <unistd.h>
#include <sys/utsname.h>
#include <net/if.h>
#if !defined(__ANDROID__) || __ANDROID_API__ >= 24
#include <ifaddrs.h>
#define LWS_HAVE_IFADDRS
#endif
#if defined(__linux__)
#include <sys/sysinfo.h>
#endif
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__) || defined(__DragonFly__)
#include <sys/sysctl.h>
#define LWS_HAVE_KERN_BOOTTIME
#endif

void
lws_plat_sysinfo_fill(struct lws_sysinfo *si)
{
	struct utsname un;
	char buf[256];

	if (!gethostname(buf, sizeof(buf) - 1)) {
		buf[sizeof(buf) - 1] = '\0';
		lws_sysinfo_add(si, LWS_SYSINFO_HOSTNAME, NULL, buf, 0);
	}

	if (!uname(&un)) {
		lws_snprintf(buf, sizeof(buf), "%s %s", un.sysname, un.release);
		lws_sysinfo_add(si, LWS_SYSINFO_OS, NULL, buf, 0);
		lws_sysinfo_add(si, LWS_SYSINFO_ARCH, NULL, un.machine, 0);
	}

	lws_sysinfo_add(si, LWS_SYSINFO_PID, NULL, NULL, (uint64_t)getpid());

#if defined(_SC_NPROCESSORS_ONLN)
	{
		long n = sysconf(_SC_NPROCESSORS_ONLN);

		if (n > 0)
			lws_sysinfo_add(si, LWS_SYSINFO_CPUS, NULL, NULL,
					(uint64_t)n);
	}
#endif

	/*
	 * RAM: sysconf() has the page counts on linux, the BSDs and macOS
	 * (which has no free count that way, and none here)
	 */
#if defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
	{
		long pages = sysconf(_SC_PHYS_PAGES), ps = sysconf(_SC_PAGESIZE);

		if (pages > 0 && ps > 0)
			lws_sysinfo_add(si, LWS_SYSINFO_RAM_TOTAL, NULL, NULL,
					(uint64_t)pages * (uint64_t)ps);
#if defined(_SC_AVPHYS_PAGES)
		pages = sysconf(_SC_AVPHYS_PAGES);
		if (pages > 0 && ps > 0)
			lws_sysinfo_add(si, LWS_SYSINFO_RAM_FREE, NULL, NULL,
					(uint64_t)pages * (uint64_t)ps);
#endif
	}
#endif

	/* uptime */
#if defined(__linux__)
	{
		struct sysinfo s;

		if (!sysinfo(&s))
			lws_sysinfo_add(si, LWS_SYSINFO_UPTIME, NULL, NULL,
					(uint64_t)s.uptime);
	}
#elif defined(LWS_HAVE_KERN_BOOTTIME)
	{
		int mib[2] = { CTL_KERN, KERN_BOOTTIME };
		struct timeval bt;
		size_t l = sizeof(bt);

		if (!sysctl(mib, 2, &bt, &l, NULL, 0) && bt.tv_sec)
			lws_sysinfo_add(si, LWS_SYSINFO_UPTIME, NULL, NULL,
					(uint64_t)(lws_now_secs() -
						   (uint64_t)bt.tv_sec));
	}
#endif

	/* every address on every interface */
#if defined(LWS_HAVE_IFADDRS)
	{
		struct ifaddrs *ifr, *ifc;

		if (getifaddrs(&ifr)) {
			lwsl_cx_info(si->cx, "getifaddrs failed, errno %d",
				     errno);
			return;
		}

		for (ifc = ifr; ifc; ifc = ifc->ifa_next) {
			uint32_t flags = 0;

			if (!ifc->ifa_addr || !ifc->ifa_name)
				continue;

			if (ifc->ifa_flags & IFF_UP)
				flags |= LWS_SYSINFO_IF_UP;
			if (ifc->ifa_flags & IFF_RUNNING)
				flags |= LWS_SYSINFO_IF_RUNNING;
			if (ifc->ifa_flags & IFF_LOOPBACK)
				flags |= LWS_SYSINFO_IF_LOOPBACK;
			if (ifc->ifa_flags & IFF_POINTOPOINT)
				flags |= LWS_SYSINFO_IF_P2P;

			/* not an address family we deal in: skipped inside */
			lws_sysinfo_add_iface(si, ifc->ifa_name, ifc->ifa_addr,
					      ifc->ifa_netmask, -1, flags);
		}

		freeifaddrs(ifr);
	}
#endif
}
