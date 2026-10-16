# System information snapshot

## Why

A daemon's logs are read somewhere else, often long after the fact, and the
first thing the reader wants to know is what the machine looked like: what it
called itself, which addresses it had on which interfaces, which nameservers
it was using, what time it thought it was, and which build of lws it was
running.  Most of that is platform-specific to find out, and every program
that wanted it had its own partial version.

`lws_sysinfo` takes one snapshot of all of it, the same way on every
platform lws builds for, as a list the caller walks, and renders each item as
a line of text for logging.

## What's in it

Item | What
---|---
`LWS_SYSINFO_LWS_VERSION` | the lws library version
`LWS_SYSINFO_LWS_BUILD` | the lws build's git hash
`LWS_SYSINFO_HOSTNAME` | what the system calls itself
`LWS_SYSINFO_OS` | the OS and its version, eg, `Linux 6.12.3` or `Windows 10.0.22631`
`LWS_SYSINFO_ARCH` | the machine architecture, eg, `x86_64`
`LWS_SYSINFO_PID` | our process id
`LWS_SYSINFO_TIME` | the system's time as unix seconds, and as ISO 8601 UTC
`LWS_SYSINFO_UPTIME` | seconds since the system booted
`LWS_SYSINFO_CPUS` | the cpus we may run on
`LWS_SYSINFO_RAM_TOTAL` | bytes of RAM in the system
`LWS_SYSINFO_RAM_FREE` | bytes of RAM not in use
`LWS_SYSINFO_IFACE_ADDR` | one per address on every interface: the interface name, the address, its prefix length and whether the interface is up, running, loopback or point-to-point
`LWS_SYSINFO_DNS_SERVER` | one per nameserver the resolver uses
`LWS_SYSINFO_DNS_SEARCH` | one per domain in the resolver's search list, with ndots

An item a platform can't provide is simply not there: eg, macOS has no free
RAM count the way the others do, and an ESP32 has no hostname or RAM total.
The resolver items need `LWS_WITH_SYS_ASYNC_DNS`.

Platform | Source
---|---
unix (linux, BSDs, macOS, android) | `gethostname()`, `uname()`, `sysconf()`, `sysinfo()` or `KERN_BOOTTIME`, `getifaddrs()`
windows | `gethostname()`, `RtlGetVersion()`, `GetNativeSystemInfo()`, `GlobalMemoryStatusEx()`, `GetTickCount64()`, `GetAdaptersAddresses()`
freertos / esp32 | `esp_timer_get_time()`, `esp_get_free_heap_size()`, lwip's `netif_list`

## Using it

```
	struct lws_sysinfo *si = lws_sysinfo_create(context);
	const lws_sysinfo_item_t *it = NULL;
	char line[256];

	while ((it = lws_sysinfo_next(si, it))) {
		lws_sysinfo_describe(it, line, sizeof(line));
		lwsl_notice("sysinfo: %s\n", line);
	}

	lws_sysinfo_destroy(&si);
```

gives something like

```
sysinfo: lws version: 5.0.99-sai-42ed2b8dc-19-g7444b03a9
sysinfo: lws build: sai-42ed2b8dc-19-g7444b03a9
sysinfo: time: 2026-10-16T08:01:02Z (unix 1792137662)
sysinfo: hostname: noi
sysinfo: os: Linux 6.12.3
sysinfo: arch: x86_64
sysinfo: pid: 1325397
sysinfo: cpus: 16
sysinfo: ram total: 63890 MiB (66995494912)
sysinfo: ram free: 41204 MiB (43206180864)
sysinfo: uptime: 12d 3h 7m 41s
sysinfo: iface lo: 127.0.0.1/8 up running loopback
sysinfo: iface lo: ::1/128 up running loopback
sysinfo: iface enp5s0: 10.199.57.11/16 up running
sysinfo: iface enp5s0: fe80::1a2b:3c4d:5e6f:7a8b/64 up running
sysinfo: iface virbr0: 192.168.122.1/24 up
sysinfo: dns server: 10.199.0.10
sysinfo: dns search: lan (ndots 1)
```

The items are `lws_sysinfo_item_t`: the type, a `name` (the interface, for
an address), a string `s`, a number `u`, an `lws_sockaddr46` `sa46` for the
address types, and `flags` for an interface address.  A caller that wants
the data rather than the text, eg, to pick the address to advertise, reads
those directly.  The snapshot is one allocation; nothing in it is valid after
`lws_sysinfo_destroy()`.

It's built with `LWS_WITH_SYS_INFO`, on by default, and needs
`LWS_WITH_NETWORK`.
