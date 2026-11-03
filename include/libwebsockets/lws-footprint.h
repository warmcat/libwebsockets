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

/** \defgroup footprint Footprint: what holds the heap
 * ##Footprint: accounting for heap by the things that hold it
 *
 * Caches, pools and lists that already exist, in lws or in user code, can
 * each embed one lws_footprint_t and register it on the context, naming the
 * source it is with a static string, eg, "JITT cache".  They keep its item
 * count and byte count as they add and free items, and may offer to dump
 * their contents or give memory back.
 *
 * The context can then say, for each participant and in total, how much heap
 * is held and by what, compare that with what the platform says is in use,
 * and, when memory is short, ask participants to shed what they can rebuild,
 * cheapest to rebuild first.
 *
 * The participants are the owners of things, not the things: nothing is kept
 * per item, a participant costs one lws_footprint_t.
 *
 * All of it, including the lws_footprint_t members owners embed, only exists
 * in builds with -DLWS_WITH_FOOTPRINT=1, whatever the CMAKE_BUILD_TYPE.
 *
 * See READMEs/README.lws_footprint.md
 */
///@{

#if defined(LWS_WITH_FOOTPRINT)

/**
 * lws_fp_shed_t - how costly it is to have a participant's memory back
 *
 * lws_footprint_shed() asks participants in this order, so what is cheapest
 * to rebuild goes first.
 */
typedef enum lws_fp_shed {
	LWSFP_SHED_NONE,
	/**< it holds nothing it can give back */
	LWSFP_SHED_IDLE,
	/**< unused leftovers: expired entries, spare pool members, objects
	 * already waiting out a grace period before they are freed */
	LWSFP_SHED_CACHE,
	/**< cached content that can be fetched or computed again */
	LWSFP_SHED_CONN,
	/**< idle connections kept for reuse, that would have to be made again,
	 * with their handshakes */
} lws_fp_shed_t;

/**
 * lws_footprint_report_t - what a participant holds
 */
typedef struct lws_footprint_report {
	size_t		count;
	/**< how many items it holds */
	size_t		bytes;
	/**< heap it holds, counting each allocation once, in the participant
	 * that frees it */
	size_t		bytes_hwm;
	/**< the most bytes it has held at once */
	size_t		sheddable;
	/**< of bytes, how many lws_footprint_shed() could have back now */
} lws_footprint_report_t;

struct lws_footprint;

/**
 * lws_footprint_ops_t - what a kind of participant can do, besides be counted
 *
 * Optional: a participant that only keeps counts registers with NULL ops.
 * Otherwise usually const and shared by every participant of one source, eg,
 * every vhost's tls context.
 *
 * The ops are called from the service thread, with the context lock held.
 * .report and .dump mustn't change what is registered.  .shed may free
 * things that unregister participants, its own included.
 */
typedef struct lws_footprint_ops {
	lws_fp_shed_t	shed_class;
	/**< how costly its memory is to have back, LWSFP_SHED_NONE if it has
	 * no .shed */

	void		(*report)(struct lws_footprint *fp,
				  lws_footprint_report_t *r);
	/**< optional: fill r.  Without it, r is the counts kept by
	 * lws_footprint_add() and friends, with nothing sheddable.  Give it
	 * when the participant works out its use on demand, or knows how much
	 * it could shed */
	void		(*dump)(struct lws_footprint *fp);
	/**< optional: log what it holds, at notice level, one line per item */
	size_t		(*shed)(struct lws_footprint *fp, size_t want);
	/**< optional: free what it can, up to about want bytes, and return how
	 * many it freed.  It must leave everything it keeps usable */
} lws_footprint_ops_t;

/**
 * lws_footprint_t - one participant, embedded in the cache, pool or list
 *
 * Zero it before lws_footprint_register(), eg, by being in a zeroed
 * allocation.  Only touch it through the api.
 */
typedef struct lws_footprint {
	lws_dll2_t			list;
	/* private: */
	const lws_footprint_ops_t	*ops;
	const char			*source;
	const char			*ident;
	size_t				count;
	size_t				bytes;
	size_t				bytes_hwm;
	unsigned int			shed_pass;
} lws_footprint_t;

/**
 * lws_footprint_register() - join the context's accounting
 *
 * \param cx: the lws context
 * \param fp: the participant's embedded lws_footprint_t
 * \param source: what it is, eg, "JITT cache".  A static string the
 *		  participant only points to, so it must stay valid as long as
 *		  the context; every participant of one kind gives the same one
 * \param ops: what it can do besides be counted, or NULL
 *
 * Register when the owner is created, before it holds anything.
 */
LWS_VISIBLE LWS_EXTERN void
lws_footprint_register(struct lws_context *cx, lws_footprint_t *fp,
		       const char *source, const lws_footprint_ops_t *ops);

/**
 * lws_footprint_set_ident() - say which one of its source a participant is
 *
 * \param fp: the participant's embedded lws_footprint_t
 * \param ident: an identifying string the owner already keeps, eg, a vhost
 *		 or host name, or NULL for none.  Only pointed to, so it must
 *		 stay valid until it is set again or the participant
 *		 unregisters
 *
 * Optional, and may be called any time after lws_footprint_register(), since
 * an owner may only learn its identity later.
 */
static LWS_INLINE void
lws_footprint_set_ident(lws_footprint_t *fp, const char *ident)
{
	fp->ident = ident;
}

/**
 * lws_footprint_unregister() - leave the context's accounting
 *
 * \param fp: the participant's embedded lws_footprint_t
 *
 * Unregister before the owner is freed.  It's harmless if it never
 * registered, or already unregistered.
 */
LWS_VISIBLE LWS_EXTERN void
lws_footprint_unregister(lws_footprint_t *fp);

/**
 * lws_footprint_add() - the participant took on an item
 *
 * \param fp: the participant's embedded lws_footprint_t
 * \param bytes: the heap the item holds
 *
 * Call it where the item is allocated, under whatever lock already protects
 * the owner's list.
 */
static LWS_INLINE void
lws_footprint_add(lws_footprint_t *fp, size_t bytes)
{
	fp->count++;
	fp->bytes += bytes;
	if (fp->bytes > fp->bytes_hwm)
		fp->bytes_hwm = fp->bytes;
}

/**
 * lws_footprint_sub() - the participant freed an item
 *
 * \param fp: the participant's embedded lws_footprint_t
 * \param bytes: the heap the item held, as given to lws_footprint_add()
 */
static LWS_INLINE void
lws_footprint_sub(lws_footprint_t *fp, size_t bytes)
{
	if (fp->count)
		fp->count--;
	fp->bytes = fp->bytes > bytes ? fp->bytes - bytes : 0;
}

/**
 * lws_footprint_resize() - an item the participant holds changed size
 *
 * \param fp: the participant's embedded lws_footprint_t
 * \param was: the bytes it held before
 * \param now: the bytes it holds now
 */
static LWS_INLINE void
lws_footprint_resize(lws_footprint_t *fp, size_t was, size_t now)
{
	fp->bytes = fp->bytes > was ? fp->bytes - was : 0;
	fp->bytes += now;
	if (fp->bytes > fp->bytes_hwm)
		fp->bytes_hwm = fp->bytes;
}

/**
 * lws_footprint_total() - what every participant holds, together
 *
 * \param cx: the lws context
 * \param r: filled with the totals; bytes_hwm is the sum of the participants'
 *	     own high water marks, so more than was ever held at once
 *
 * Returns how many participants there are.
 */
LWS_VISIBLE LWS_EXTERN int
lws_footprint_total(struct lws_context *cx, lws_footprint_report_t *r);

/**
 * lws_footprint_dump() - log what every participant holds
 *
 * \param cx: the lws context
 * \param items: also call each participant's .dump, to list its items
 *
 * Logs a line per participant at notice level, giving its source and ident
 * with its report, then the total, and the heap
 * the platform says is in use, where it can say, with the difference that
 * no participant accounts for.
 */
LWS_VISIBLE LWS_EXTERN void
lws_footprint_dump(struct lws_context *cx, int items);

/**
 * lws_footprint_shed() - ask participants to give memory back
 *
 * \param cx: the lws context
 * \param want: bytes to try to free
 * \param most: the most costly lws_fp_shed_t class to ask
 *
 * Asks the participants of each class in turn, from LWSFP_SHED_IDLE up to
 * most, until want bytes are freed or there are none left to ask.  Returns
 * how many bytes were freed, which may be less, or more, than want.
 */
LWS_VISIBLE LWS_EXTERN size_t
lws_footprint_shed(struct lws_context *cx, size_t want, lws_fp_shed_t most);

#if defined(LWS_WITH_ALLOC_SITES)

#define LWS_ALLOC_SITE_CALLERS 3

/*
 * What is live from one place that called lws_malloc() and friends: the
 * reason it gave, and, where the platform can say, who called the allocator
 * (nearest first).  bytes is what the callers asked for, not counting the
 * heap's own overhead, or the site's header.
 */
typedef struct lws_alloc_site {
	const char		*reason;
	uintptr_t		pcs[LWS_ALLOC_SITE_CALLERS];
	size_t			bytes;
	unsigned int		count;
} lws_alloc_site_t;

/**
 * lws_alloc_sites() - what lws_malloc() and friends hold now, by who asked
 *
 * \param sites: array to fill with the sites, biggest first
 * \param max: how many sites fit in the array
 * \param rest: NULL, or filled with the total of the sites that didn't fit
 *
 * The sites are ranked as they are found, so with more sites than max, the
 * ones that didn't fit, in rest, aren't necessarily the smallest: give it room
 * for all of them, eg, a few hundred, to know which are the biggest.
 *
 * Only exists in builds with LWS_WITH_ALLOC_SITES, which puts a small header
 * in front of every allocation to say who made it.  It's for finding out
 * where the heap goes that no footprint participant accounts for:
 * lws_footprint_dump() lists these after the participants.
 *
 * Returns how many sites were filled in.
 */
LWS_VISIBLE LWS_EXTERN int
lws_alloc_sites(lws_alloc_site_t *sites, int max, lws_alloc_site_t *rest);
#endif

#endif

///@}
