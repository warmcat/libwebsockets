/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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
 * Fault injection api if built with LWS_WITH_SYS_FAULT_INJECTION
 */

#if defined(LWS_WITH_SYS_FAULT_INJECTION)

enum {
	LWSFI_ALWAYS,
	LWSFI_DETERMINISTIC,	/* do .count injections after .pre then stop */
	LWSFI_PROBABILISTIC,	/* .prob1 / .prob2 chance of injection */
	LWSFI_PATTERN,		/* use .count bits in .pattern after .pre */
};

typedef struct lws_fi {
	const char		*name;
	const uint8_t		*pattern;
	uint64_t		pre;
	uint64_t		count;
	uint64_t		times;		/* start at 0, tracks usage */
	char			type;		/* LWSFI_* */
} lws_fi_t;

typedef struct lws_fi_ctx {
	lws_dll2_owner_t	fi_owner;
	const char		*name;
	struct lws_fi_ctx	*parent;
} lws_fi_ctx_t;

/**
 * lws_fi() - find out if we should perform the named fault injection this time
 *
 * \param fic: fault injection tracking context
 * \param fi_name: name of fault injection
 *
 * This checks if the named fault is configured in the fi tracking context
 * provided, if it is, then it will make a decision if the named fault should
 * be applied this time, using the tracking in the named lws_fi_t.
 *
 * If the provided context has a parent, that is also checked for the named fi
 * item recursively, with the first found being used to determine if to inject
 * or not.
 *
 * If LWS_WITH_SYS_FAULT_INJECTION is not defined, then this always return 0.
 */
LWS_VISIBLE LWS_EXTERN int
lws_fi(lws_fi_ctx_t *fic, const char *fi_name);

/**
 * lws_fi_add() - add an allocated copy of fault injection to a context
 *
 * \param fic: fault injection tracking context
 * \param fi: the fault injection details
 *
 * This allocates a copy of \p fi and attaches it to the fault injection context
 * \p fic.
 */
LWS_VISIBLE LWS_EXTERN int
lws_fi_add(lws_fi_ctx_t *fic, const lws_fi_t *fi);

/**
 * lws_fi_remove() - remove an allocated copy of fault injection from a context
 *
 * \param fic: fault injection tracking context
 * \param name: the fault injection name to remove
 *
 * This looks for the named fault injection and removes and destroys it from
 * the specified fault injection context
 */
LWS_VISIBLE LWS_EXTERN void
lws_fi_remove(lws_fi_ctx_t *fic, const char *name);

/**
 * lws_fi_destroy() - removes all allocated fault injection entries
 *
 * \param fic: fault injection tracking context
 *
 * This walks any allocated fault injection entries in \p fic and detaches and
 * destroys them.  It doesn't try to destroc \p fic itself, since this is
 * not usually directly allocated.
 */
LWS_VISIBLE LWS_EXTERN void
lws_fi_destroy(lws_fi_ctx_t *fic);

#else

/*
 * Helper so we can leave lws_fi() calls embedded in the code being tested,
 * if fault injection is not enabled then it just always says "no" at buildtime.
 */

#define lws_fi(_fi_name, _fic) (0)

#endif
