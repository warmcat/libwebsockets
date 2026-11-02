# lws_footprint: what holds the heap

On a small device, "free heap fell from 175KB to 92KB while we opened one
connection" is easy to see and hard to explain.  lws and the code using it
keep many caches, pools and lists of things whose lifetimes aren't simply
"the length of one request": tls contexts, connections kept warm for reuse,
DNS and alt-svc caches, header table pools, decoded images, fonts.  Each
already knows what it holds; nothing so far adds it up.

`lws_footprint` lets each of those owners take part in one accounting on the
context, cheaply.

## Building

It is only built with `-DLWS_WITH_FOOTPRINT=1`, which is independent of
`CMAKE_BUILD_TYPE`: release builds can have it as well as debug ones.  Without
it, none of it exists, including the `lws_footprint_t` owners embed, so
owners gate their member and every call on it:

```
struct my_cache {
	lws_dll2_owner_t	items;
#if defined(LWS_WITH_FOOTPRINT)
	lws_footprint_t		fp;
#endif
};
```

## Participants are owners, not items

A participant is a cache, pool or list that already exists, not the things in
it.  It embeds one `lws_footprint_t`, registers it on the context when it is
created and unregisters it before it is destroyed.  Nothing is kept per item,
and nothing new is allocated to take part.

It registers with a static string naming its source, eg, `"JITT cache"`, that
the participant only points to.  Every participant of one source gives the
same string, so a dump says plainly where the heap it lists is held.

If the owner has a string identifying which one it is, eg, a vhost or host
name, it can point the participant at that too with
`lws_footprint_set_ident()`, then or later, since an owner may only learn
who it is after it's created.  It's optional; the owner keeps the string
valid while it is set.

```
	lws_footprint_register(cx, &vh->tls.fp, "tls ctx", &tls_ctx_fp_ops);
	lws_footprint_set_ident(&vh->tls.fp, vh->name);
```

The owner keeps the participant's counts where it already allocates and frees
its items, under whatever lock already protects its list:

```
	lws_footprint_add(&cache->fp, sizeof(*item) + item->len);
	...
	lws_footprint_sub(&cache->fp, sizeof(*item) + item->len);
```

`lws_footprint_resize()` covers an item that grows or shrinks.

The counts are kept by the owner, of what the owner allocated, so they cost a
few adds and do not depend on the allocator.  They are only as good as the
owner's bookkeeping: each allocation should be counted once, by the
participant that frees it.  When an owner holds another owner, eg, a vhost
holding its tls context, each counts only its own allocations and both
register.

## What a participant can do

A participant that only keeps counts registers with NULL ops.  Otherwise the
participants of one source share a const `lws_footprint_ops_t`:

op|Required|Meaning
---|---|---
`shed_class`|yes|How costly its memory is to have back, see below
`report`|no|Fill in its use on demand, eg, if it can say how much is sheddable now. Without it, the counts kept by `lws_footprint_add()` are reported
`dump`|no|Log what it holds, one line per item, at notice level, since it is only called when a dump with `items` was asked for
`shed`|no|Free what it can, up to about the bytes asked for, and say how many it freed

The ops are called from the service thread with the context lock held.  They
mustn't allocate or call back into the footprint api.

## Seeing it

`lws_footprint_dump(cx, items)` logs a line per participant at notice level:
its source, its ident if it has one, count, bytes now, its high water mark and how much it
could shed.  Then it logs the total and, where the platform can say:

 - on freertos, the free heap, how much of it has gone since the context was
   created, and how much of that no participant accounts for: allocations in
   code that doesn't take part yet, or a leak

 - on platforms that can size an allocation (glibc, ESP-IDF), what
   `lws_malloc()` and friends hold now

Comparing two dumps, eg, before and after a page load, shows which
participants grew and whether the unaccounted part did.

When an lws allocation fails, even after asking the reclaimable heap
occupants to give memory back, the first context's participants are dumped
by themselves, preceded by a warning naming the allocation, at most once
every five seconds.  So the dump that matters most, what was holding the heap
when it ran out, needs no call from the application.  Builds with
`LWS_MAX_SMP` more than 1 don't do this, since the failing thread may hold
locks that mustn't be held taking the context lock.

With `items` set, each participant's `dump` op also lists what it holds.

`lws_footprint_total()` gives the totals to code that wants to act on them.

## Giving memory back

Each participant declares the class of what it can shed:

class|What it is|Cost of having it back
---|---|---
`LWSFP_SHED_NONE`|Holds nothing it can give back|-
`LWSFP_SHED_IDLE`|Expired entries, spare pool members, objects waiting out a grace period|Almost nothing
`LWSFP_SHED_CACHE`|Cached content|Fetching or computing it again when it's next needed
`LWSFP_SHED_CONN`|Idle connections kept for reuse|A new connection, with its handshake

`lws_footprint_shed(cx, want, most)` asks the participants of each class in
that order, up to `most`, until `want` bytes have been freed.  So an
application about to do something heap-hungry, like laying out a complex
page, can first ask for idle leftovers and caches back, and only lose warm
connections if that wasn't enough.

What a participant keeps after shedding must stay usable; shedding only
changes how much later work costs, never whether it works.

## Participants in lws

participant|source|ident|what it counts
---|---|---|---
Each vhost|`"vhost"`|vhost name|the vhost itself; its tls ctx is in `"mbedtls"`
The tls library's own allocations, through mbedtls' allocator hook|`"mbedtls"`|-|tls contexts, sessions, handshakes, cipher contexts
Each QUIC connection|`"quic conn"`|vhost name|itself, its keys and congestion control state, frames queued and in flight, held packets, crypto and stream reassembly
Each pt's header table pool, while it has any|`"ah pool"`|-|each ah and its header data
Each html document being fetched and laid out|`"html doc"`|url|the html received so far, the parser's css lwsacs and open elements
Each display list bound to a context|`"display list"`|-|every dlo, and images' payloads, decoders and rows; the `items` dump lists the dlos holding more than 1KB, by name

Participants that work out what they hold on demand, rather than counting as
they go, size each allocation with `lws_fp_heap()`: what the platform says
the allocation holds where it can say, else the size that was asked for.

The mbedtls participant is the only way to see what the tls library itself
allocates, which no lws owner can.  It is installed with
`mbedtls_platform_set_calloc_free()` when the first context is created, so it
needs mbedtls built with `MBEDTLS_PLATFORM_MEMORY` and without
`MBEDTLS_PLATFORM_CALLOC_MACRO` / `MBEDTLS_PLATFORM_FREE_MACRO`, as ESP-IDF
builds it.  Otherwise there is no "mbedtls" participant.

Each of mbedtls' allocations gets a small header listing it with its size and,
where the platform can say (`LWS_PLAT_CALLERS`: ESP-IDF on Xtensa, and unix
builds with `LWS_WITH_CRASH_BACKTRACE`), the four nearest callers of
`mbedtls_calloc()`.  With `items`, the dump lists mbedtls' heap grouped by
those callers, biggest first, eg

```
fp:       16768 B   1 x from 0x401d6b2c 0x401d9e54 0x40128a10 0x40127f3c
```

`idf.py monitor` turns the addresses into function names and lines by
itself; elsewhere, `addr2line -e` the binary.  The headers cost heap too, and
the dump says how much, so it can be discounted.

The hook is process-wide: it lists mbedtls' allocations made by anything in
the process, eg, a wifi supplicant on another task, and it replaces any
allocator an application set with `mbedtls_platform_set_calloc_free()`
before creating the context.

## Planned participants

participant|source|shed class
---|---|---
JIT Trust vhosts in their grace period|`"vhost"`|IDLE
Idle h2 connections kept for reuse|`"h2 conn"`|CONN
The context's `lws_cache_ttl` caches|`"dns cache"`, `"alt-svc cache"`, `"h3 cap cache"`, `"trust cache"`|CACHE
The dlo asset cache and the reclaimable heap occupants (fonts, decoded images)|`"dlo asset cache"`, `"reclaimable"`|CACHE
Secure Streams handles|`"ss handles"`|NONE

`lws_cache_ttl` and `lwsac` already track their own sizes, so they take part
by reporting what they already know.

## Later

 - A low free heap threshold in the context creation info, so the platform's
   periodic heap check can call `lws_footprint_shed()` itself on small
   devices.

