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

#include <iphlpapi.h>

typedef LONG (WINAPI *lws_rtlgetversion_t)(PRTL_OSVERSIONINFOW);

void
lws_plat_sysinfo_fill(struct lws_sysinfo *si)
{
	IP_ADAPTER_ADDRESSES *aa = NULL, *a;
	MEMORYSTATUSEX ms;
	SYSTEM_INFO sysi;
	ULONG al = 16384;
	char buf[256];
	HMODULE h;
	int n = 0;

	if (!gethostname(buf, sizeof(buf) - 1)) {
		buf[sizeof(buf) - 1] = '\0';
		lws_sysinfo_add(si, LWS_SYSINFO_HOSTNAME, NULL, buf, 0);
	}

	/*
	 * GetVersionEx() lies to apps that don't declare compatibility, the
	 * kernel's RtlGetVersion() doesn't
	 */
	h = GetModuleHandleW(L"ntdll.dll");
	if (h) {
		lws_rtlgetversion_t rgv = (lws_rtlgetversion_t)
					GetProcAddress(h, "RtlGetVersion");
		RTL_OSVERSIONINFOW vi;

		memset(&vi, 0, sizeof(vi));
		vi.dwOSVersionInfoSize = sizeof(vi);
		if (rgv && !rgv(&vi)) {
			lws_snprintf(buf, sizeof(buf), "Windows %u.%u.%u",
				     (unsigned int)vi.dwMajorVersion,
				     (unsigned int)vi.dwMinorVersion,
				     (unsigned int)vi.dwBuildNumber);
			lws_sysinfo_add(si, LWS_SYSINFO_OS, NULL, buf, 0);
		}
	}

	GetNativeSystemInfo(&sysi);
	switch (sysi.wProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_AMD64:
		lws_sysinfo_add(si, LWS_SYSINFO_ARCH, NULL, "x86_64", 0);
		break;
	case PROCESSOR_ARCHITECTURE_INTEL:
		lws_sysinfo_add(si, LWS_SYSINFO_ARCH, NULL, "x86", 0);
		break;
#if defined(PROCESSOR_ARCHITECTURE_ARM64)
	case PROCESSOR_ARCHITECTURE_ARM64:
		lws_sysinfo_add(si, LWS_SYSINFO_ARCH, NULL, "aarch64", 0);
		break;
#endif
	case PROCESSOR_ARCHITECTURE_ARM:
		lws_sysinfo_add(si, LWS_SYSINFO_ARCH, NULL, "arm", 0);
		break;
	default:
		break;
	}
	if (sysi.dwNumberOfProcessors)
		lws_sysinfo_add(si, LWS_SYSINFO_CPUS, NULL, NULL,
				(uint64_t)sysi.dwNumberOfProcessors);

	lws_sysinfo_add(si, LWS_SYSINFO_PID, NULL, NULL,
			(uint64_t)GetCurrentProcessId());
	lws_sysinfo_add(si, LWS_SYSINFO_UPTIME, NULL, NULL,
			(uint64_t)(GetTickCount64() / 1000));

	memset(&ms, 0, sizeof(ms));
	ms.dwLength = sizeof(ms);
	if (GlobalMemoryStatusEx(&ms)) {
		lws_sysinfo_add(si, LWS_SYSINFO_RAM_TOTAL, NULL, NULL,
				(uint64_t)ms.ullTotalPhys);
		lws_sysinfo_add(si, LWS_SYSINFO_RAM_FREE, NULL, NULL,
				(uint64_t)ms.ullAvailPhys);
	}

	/* every unicast address on every adapter */

	do {
		ULONG r;

		aa = (IP_ADAPTER_ADDRESSES *)lws_malloc(al, __func__);
		if (!aa)
			return;

		r = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST |
					 GAA_FLAG_SKIP_MULTICAST |
					 GAA_FLAG_SKIP_DNS_SERVER, NULL, aa,
					 &al);
		if (r == NO_ERROR)
			break;

		lws_free(aa);
		aa = NULL;
		if (r != ERROR_BUFFER_OVERFLOW || n++)
			return;
	} while (1);

	for (a = aa; a; a = a->Next) {
		IP_ADAPTER_UNICAST_ADDRESS *ua;
		uint32_t flags = 0;
		char name[128];

		if (a->OperStatus == IfOperStatusUp)
			flags |= LWS_SYSINFO_IF_UP | LWS_SYSINFO_IF_RUNNING;
		if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
			flags |= LWS_SYSINFO_IF_LOOPBACK;
		if (a->IfType == IF_TYPE_PPP)
			flags |= LWS_SYSINFO_IF_P2P;

		if (!a->FriendlyName ||
		    WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, name,
					sizeof(name), NULL, NULL) <= 0)
			lws_strncpy(name, a->AdapterName ? a->AdapterName : "?",
				    sizeof(name));

		for (ua = a->FirstUnicastAddress; ua; ua = ua->Next)
			lws_sysinfo_add_iface(si, name, ua->Address.lpSockaddr,
					      NULL, (int)ua->OnLinkPrefixLength,
					      flags);
	}

	lws_free(aa);
}
