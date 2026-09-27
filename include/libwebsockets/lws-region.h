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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/** \defgroup region Region ownership
 * ##lws_region: who holds which range of a shared scratch buffer
 *
 * A scratch buffer shared by several users, to avoid allocations, is only
 * sound while each range of it has one user at a time.  Ownership can be
 * legitimately fragmented: a parser may still hold the unparsed tail of a
 * read while a composer uses the already-consumed part below it.
 *
 * lws_region makes that rule checkable.  Each user claims the range it is
 * about to use, with a name, and releases it when done.  A claim that
 * overlaps a live one fails naming both.  A claim may give back its consumed
 * prefix (lws_region_trim()), or be released by any pointer inside it
 * (lws_region_release_containing()), which is how one user hands a buffer on
 * to another without knowing its handle.  lws_region_idle() confirms nothing
 * is held, eg, at a point where the buffer's contents stop being meaningful.
 *
 * Pointers outside the buffer are not tracked and are ignored by every call,
 * so code that may be given either the shared buffer or some other storage
 * can make the same calls regardless.
 *
 * Nothing is allocated: the caller provides the lws_region_t and the table
 * of claim slots, sized for how many claims may be live at once.
 *
 * With LWS_REGION_F_ABORT, a violation is logged and then abort()s, so a
 * debug build stops at the first one with both parties named; without it,
 * the violation is logged and reported in the return code.
 */
///@{

/** a claim slot: members are private to the lws_region_...() apis */
typedef struct lws_region_claim {
	const uint8_t		*s;	/* NULL: slot free */
	const uint8_t		*e;
	const char		*who;
	uint16_t		gen;	/* distinguishes reuses of the slot */
} lws_region_claim_t;

/** the tracked buffer: members are private to the lws_region_...() apis */
typedef struct lws_region {
	const char		*name;
	const uint8_t		*base;
	size_t			len;
	lws_region_claim_t	*claims;
	uint8_t			count_claims;
	uint8_t			flags;
} lws_region_t;

/* lws_region_init() flags */
#define LWS_REGION_F_ABORT		(1 << 0)  /* abort() on violation */

/* lws_region_claim() results other than a handle */
enum {
	LWS_REGION_NOT_TRACKED		= -1, /* p is not in the buffer */
	LWS_REGION_E_OVERRUN		= -2, /* runs past the end */
	LWS_REGION_E_OVERLAP		= -3, /* overlaps a live claim */
	LWS_REGION_E_FULL		= -4, /* no free claim slot */
};

/**
 * lws_region_init() - start tracking claims on a buffer
 *
 * \param r: the region object to initialize
 * \param name: name of the buffer for logging, must outlive r
 * \param base: start of the buffer
 * \param len: length of the buffer
 * \param claims: caller-provided table of claim slots
 * \param count_claims: how many slots in claims, 1..255
 * \param flags: LWS_REGION_F_...
 *
 * Returns 0, or -1 if count_claims is out of range.  All slots start free.
 */
LWS_VISIBLE LWS_EXTERN int
lws_region_init(lws_region_t *r, const char *name, const void *base,
		size_t len, lws_region_claim_t *claims, size_t count_claims,
		unsigned int flags);

/**
 * lws_region_claim() - claim len bytes at p for who
 *
 * \param r: the region
 * \param p: start of the range being claimed
 * \param len: length of the range
 * \param who: name of the claimant for logging, must outlive the claim
 *
 * Returns a handle >= 0 for lws_region_release(), LWS_REGION_NOT_TRACKED if
 * p is not inside the buffer (nothing is recorded, and releasing that result
 * is a NOP), or an LWS_REGION_E_... error after logging it, if the flags did
 * not have it abort instead.
 */
LWS_VISIBLE LWS_EXTERN int
lws_region_claim(lws_region_t *r, const void *p, size_t len, const char *who);

/**
 * lws_region_release() - release a claim by its handle
 *
 * \param r: the region
 * \param handle: what lws_region_claim() returned for it
 *
 * Negative handles are ignored.  So is a handle whose claim was already
 * given up by lws_region_trim() or lws_region_release_containing(), even if
 * the slot has since been reused by another claim.
 */
LWS_VISIBLE LWS_EXTERN void
lws_region_release(lws_region_t *r, int handle);

/**
 * lws_region_release_containing() - release whichever claim covers p
 *
 * \param r: the region
 * \param p: any pointer inside the claim, inclusive of its end
 *
 * For handing the buffer on without the claimant's handle.  If p is not
 * inside any live claim, it is a NOP.
 */
LWS_VISIBLE LWS_EXTERN void
lws_region_release_containing(lws_region_t *r, const void *p);

/**
 * lws_region_trim() - give back the prefix of a claim below p
 *
 * \param r: the region
 * \param p: the new start of the claim covering p
 *
 * The claim covering p then starts at p; if p is at its end, the claim is
 * given up entirely.  If p is not inside any live claim, it is a NOP.
 */
LWS_VISIBLE LWS_EXTERN void
lws_region_trim(lws_region_t *r, const void *p);

/**
 * lws_region_idle() - confirm nothing holds any of the buffer
 *
 * \param r: the region
 * \param where: name of the checkpoint for logging
 *
 * Returns 0 if no claim is live, else logs the first live one and returns
 * -1, if the flags did not have it abort instead.
 */
LWS_VISIBLE LWS_EXTERN int
lws_region_idle(const lws_region_t *r, const char *where);

///@}
