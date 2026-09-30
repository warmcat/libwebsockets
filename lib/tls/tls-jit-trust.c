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
 */

#include "private-lib-core.h"

void
lws_tls_kid_copy(union lws_tls_cert_info_results *ci, lws_tls_kid_t *kid)
{

	/*
	 * KIDs all seem to be 20 bytes / SHA1 or less.  If we get one that
	 * is bigger, treat only the first 20 bytes as significant.
	 */

	if ((size_t)ci->ns.len > sizeof(kid->kid))
		kid->kid_len = sizeof(kid->kid);
	else {
#if defined(__COVERITY__)
		kid->kid_len = 0;
#else
		kid->kid_len = (uint8_t)ci->ns.len;
#endif
	}

	memcpy(kid->kid, ci->ns.name, kid->kid_len);
}

void
lws_tls_kid_copy_kid(lws_tls_kid_t *kid, const lws_tls_kid_t *src)
{
	int klen = sizeof(kid->kid);

	if (src->kid_len < klen)
		klen = src->kid_len;

	kid->kid_len = (uint8_t)klen;

	memcpy(kid->kid, src->kid, (size_t)klen);
}

int
lws_tls_kid_cmp(const lws_tls_kid_t *a, const lws_tls_kid_t *b)
{
	if (a->kid_len != b->kid_len)
		return 1;

	return memcmp(a->kid, b->kid, a->kid_len);
}

/*
 * We have the SKID and AKID for every peer cert captured, but they may be
 * in any order, and eg, falsely have sent the root CA, or an attacker may
 * send unresolveable self-referencing loops of KIDs.  Certs are also not
 * obliged to carry an SKID at all: Let's Encrypt leaf certs, for one, don't.
 *
 * Let's sort them into the SKID -> AKID hierarchy, so the last entry is the
 * server cert and the first entry is the highest parent that the server sent.
 * Normally the top one will be an intermediate, and its AKID is the ID of the
 * root CA cert we would need to trust to validate the chain.  Anything that
 * is not on the path up from the server cert (eg, an alternative cross-signed
 * intermediate) is kept, ahead of the path.
 *
 * This doesn't decide what we query, since we query every AKID anyway, so it
 * is not trying to be clever about hostile input, just to always end in a
 * bounded number of steps, whatever order and relationships we were given.
 */

static void
lws_tls_jit_trust_order_chain(lws_tls_kid_chain_t *ch)
{
	int n, m, leaf = -1, next, depth = 0;
	lws_tls_kid_chain_t o;
	uint8_t path[LWS_ARRAY_SIZE(ch->akid)];
	unsigned int used = 0;

	/*
	 * The server cert is the one that no other cert names as its
	 * issuer... one with no SKID can't be anybody's issuer.  If every cert
	 * is somebody's issuer, it's a loop, just start from the first.
	 */

	for (n = 0; n < ch->count && leaf < 0; n++) {
		for (m = 0; m < ch->count; m++)
			if (m != n && ch->skid[n].kid_len &&
			    !lws_tls_kid_cmp(&ch->skid[n], &ch->akid[m]))
				break;
		if (m == ch->count)
			leaf = n;
	}

	if (leaf < 0)
		leaf = 0;

	/* walk up from it, following AKID -> SKID, using each cert once */

	next = leaf;
	while (next >= 0) {
		used |= 1u << next;
		path[depth++] = (uint8_t)next;
		n = next;
		next = -1;

		if (!ch->akid[n].kid_len)
			break;

		for (m = 0; m < ch->count; m++)
			if (!(used & (1u << m)) &&
			    !lws_tls_kid_cmp(&ch->akid[n], &ch->skid[m])) {
				next = m;
				break;
			}
	}

	/* the certs off the path first, then the path from the top down */

	memset(&o, 0, sizeof(o));

	for (n = 0; n < ch->count; n++)
		if (!(used & (1u << n))) {
			o.akid[o.count] = ch->akid[n];
			o.skid[o.count++] = ch->skid[n];
		}

	while (depth--) {
		o.akid[o.count] = ch->akid[path[depth]];
		o.skid[o.count++] = ch->skid[path[depth]];
	}

	*ch = o;
}

/*
 * Two certs in the chain may name the same issuer, eg, the same intermediate
 * sent twice.  It's only worth asking for it once, and a CA that came back
 * twice would also cancel itself out of the xor vhost tag.
 */

static int
lws_tls_jit_trust_akid_is_repeat(const lws_tls_kid_chain_t *ch, int n)
{
	int m;

	for (m = 0; m < n; m++)
		if (!lws_tls_kid_cmp(&ch->akid[m], &ch->akid[n]))
			return 1;

	return 0;
}

/*
 * The trust cache and the inflights are keyed on the endpoint the trust was
 * learned from.  Another port on the same address, or another name served
 * from it, is another server, that may be validated another way... eg, by the
 * app's own CA on the vhost that a JIT Trust vhost would displace for it.
 *
 * The host is the name the server is validated as, and defaults to the
 * address like it does for the tls session cache.  The address length leads,
 * so no address and host pair can spell the key of another.
 *
 * Returns 0 with the key in key[], or nonzero if there is none that fits.
 */

static int
lws_tls_jit_trust_key(char *key, size_t len, const char *address,
		      uint16_t port, const char *host)
{
	int n;

	if (!address || !*address)
		return 1;

	if (!host || !*host || !strcmp(host, address))
		n = lws_snprintf(key, len, "%u:%u:%s", (unsigned int)port,
				 (unsigned int)strlen(address), address);
	else
		n = lws_snprintf(key, len, "%u:%u:%s:%s", (unsigned int)port,
				 (unsigned int)strlen(address), address, host);

	return n >= (int)len;
}

/*
 * A client wsi's own endpoint key, from the same connect info that
 * lws_tls_jit_trust_vhost_bind() is given at connect (and redirect) time.
 */

static int
lws_tls_jit_trust_wsi_key(struct lws *wsi, char *key, size_t len)
{
	return lws_tls_jit_trust_key(key, len,
			lws_wsi_client_stash_item(wsi, CIS_ADDRESS,
					_WSI_TOKEN_CLIENT_PEER_ADDRESS),
			wsi->c_port,
			lws_wsi_client_stash_item(wsi, CIS_HOST,
					_WSI_TOKEN_CLIENT_HOST));
}

static void
tag_to_vh_name(char *result, size_t max, uint32_t tag)
{
	lws_snprintf(result, max, "jitt-%08X", (unsigned int)tag);
}

/*
 * If we return 0, we succeeded and have queried the system for every CA that
 * a cert in the chain named as its issuer.
 *
 * If we return nonzero, we can't identify what we want and should abandon the
 * connection.
 */

/*
 * Locking: with LWS_MAX_SMP > 1, the tls verify paths that end up here and
 * connection attempts binding to a JIT Trust vhost run on every service
 * thread, and an async jit_trust_query() may complete on a thread of the
 * app's.  So the context's inflight list and trust cache are only touched
 * under the context lock, by the locked entry points below; their __ bodies
 * expect it held.  It is recursive, so a synchronous jit_trust_query()
 * completing into lws_tls_jit_trust_got_cert_cb() inside the query loop is
 * fine, and it keeps any other thread's completion of the same inflight out
 * until the loop is done with it.
 */

static int
__lws_tls_jit_trust_sort_kids(struct lws *wsi, lws_tls_kid_chain_t *ch)
{
	char key[LWS_JIT_TRUST_KEY_MAX];
	lws_tls_jit_inflight_t *inf;
	int n, q = 0;
	size_t kl;

	lwsl_info("%s\n", __func__);

	/*
	 * The trust cache entry we are going to write below is read back by
	 * lws_tls_jit_trust_vhost_bind() using the endpoint the connection
	 * was asked for, so we have to key it on that too.
	 *
	 * lws_wsi_client_stash_item() also takes care of the case there is no
	 * stash, and of builds with neither H1 nor H2.
	 */

	if (lws_tls_jit_trust_wsi_key(wsi, key, sizeof(key)))
		return 1;

	kl = strlen(key);

	/* something to work with? */

	if (!ch->count || (size_t)ch->count > LWS_ARRAY_SIZE(ch->akid))
		return 1;

	lws_tls_jit_trust_order_chain(ch);

	for (n = 0; n < ch->count; n++) {
		lwsl_info("%s: AKID[%d]\n", __func__, n);
		lwsl_hexdump_info(ch->akid[n].kid, ch->akid[n].kid_len);
		lwsl_info("%s: SKID[%d]\n", __func__, n);
		lwsl_hexdump_info(ch->skid[n].kid, ch->skid[n].kid_len);
	}

	/* to go further, user must provide a lookup helper */

	if (!wsi->a.context->system_ops ||
	    !wsi->a.context->system_ops->jit_trust_query)
		return 1;

	/*
	 * If there's already a pending lookup for this host, let's bail and
	 * just wait for that to complete (since it will be done async if we
	 * can see it)
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&wsi->a.context->jit_inflight)) {
		inf = lws_container_of(d, lws_tls_jit_inflight_t, list);

		if (!strcmp((const char *)&inf[1], key))
			/* already being handled */
			return 1;

	} lws_end_foreach_dll(d);

	/*
	 * Only AKIDs we can actually look something up with are worth a query,
	 * and only those may be counted into the inflight refcount... a
	 * zero-length AKID is rejected out of hand by the trust query (there is
	 * nothing to match on), so if we counted it here the inflight would
	 * never reach refcount 0 and would leak until context destroy.
	 *
	 * If none of them are usable, we cannot identify any CA to ask for, and
	 * we must fail the connection rather than pretend we tried.
	 */

	for (n = 0; n < ch->count; n++)
		if (ch->akid[n].kid_len &&
		    !lws_tls_jit_trust_akid_is_repeat(ch, n))
			q++;

	if (!q) {
		lwsl_info("%s: no usable AKID in the peer chain\n", __func__);

		return 1;
	}

	/*
	 * No... let's make an inflight entry for this host, then
	 */

	inf = lws_zalloc(sizeof(*inf) + kl + 1, __func__);
	if (!inf)
		return 1;

	memcpy(&inf[1], key, kl + 1);
	inf->refcount = (char)q;
	lws_dll2_add_tail(&inf->list, &wsi->a.context->jit_inflight);

	/*
	 * ...kid_chain[0] AKID should indicate the right CA SKID that we want.
	 *
	 * Because of cross-signing, we check all of them and accept we may get
	 * multiple (the inflight accepts up to 2) CAs needed.
	 */

	for (n = 0; n < ch->count; n++) {
		if (!ch->akid[n].kid_len ||
		    lws_tls_jit_trust_akid_is_repeat(ch, n))
			continue;
		wsi->a.context->system_ops->jit_trust_query(wsi->a.context,
			ch->akid[n].kid, (size_t)ch->akid[n].kid_len,
			(void *)inf);
	}

	return 0;
}

int
lws_tls_jit_trust_sort_kids(struct lws *wsi, lws_tls_kid_chain_t *ch)
{
	struct lws_context *cx = wsi->a.context;
	int n;

	lws_context_lock(cx, __func__); /* ------------------------- cx { */
	n = __lws_tls_jit_trust_sort_kids(wsi, ch);
	lws_context_unlock(cx); /* ------------------------------------ } cx */

	return n;
}

static int
__lws_tls_jit_trust_vhost_bind(struct lws_context *cx, const char *address,
			       uint16_t port, const char *host,
			       struct lws_vhost **pvh)
{
	char key[LWS_JIT_TRUST_KEY_MAX], vhtag[32];
	lws_tls_jit_cache_item_t *ci, jci;
	lws_tls_jit_inflight_t *inf;
	size_t size;
	int n;

	if (!cx->trust_cache ||
	    lws_tls_jit_trust_key(key, sizeof(key), address, port, host) ||
	    lws_cache_item_get(cx->trust_cache, key, (const void **)&ci,
									&size) ||
	    size != sizeof(jci))
		/*
		 * There's no cached info, we have to start from scratch on
		 * this one
		 */
		return 1;

	/* gotten cache item may be evicted by jit_trust_query */
	jci = *ci;

	if (jci.count_skids <= 0 ||
	    jci.count_skids > (int)LWS_ARRAY_SIZE(jci.skids))
		/*
		 * Not something we wrote, or nothing we can query with...
		 * count_skids is used below as a loop bound and as the inflight
		 * refcount, so it has to be sane before we act on it
		 */
		return 1;

	/*
	 * We have some trust cache information for this host already, it tells
	 * us the trusted CA SKIDs we found before, and the xor tag used to name
	 * the vhost configured for these trust CAs in its SSL_CTX.
	 *
	 * Let's check first if the correct prepared vhost already exists, if
	 * so, we can just bind to that and go.
	 */

	tag_to_vh_name(vhtag, sizeof(vhtag), jci.xor_tag);

	*pvh = lws_get_vhost_by_name(cx, vhtag);
	if (*pvh) {
		lwsl_info("%s: %s -> existing %s\n", __func__, key, vhtag);
		/* hit, let's just use that then */
		return 0;
	}

	/*
	 * ... so, we know the SKIDs of the missing CAs, but we don't have the
	 * DERs for them, and so no configured vhost trusting them yet.  We have
	 * had the DERs at some point, but we can't afford to cache them, so
	 * we will have to get them again.
	 *
	 * Let's make an inflight for this, it will create the vhost when it
	 * completes.  If syncrhronous, then it will complete before we leave
	 * here, otherwise it will have a life of its own until all the
	 * queries use the cb to succeed or fail.
	 */

	size = strlen(key);
	inf = lws_zalloc(sizeof(*inf) + size + 1, __func__);
	if (!inf)
		return 1;

	memcpy(&inf[1], key, size + 1);
	inf->refcount = (char)jci.count_skids;
	/* what we regenerate is only good for as long as what we learned */
	inf->expires = jci.expires;
	lws_dll2_add_tail(&inf->list, &cx->jit_inflight);

	/*
	 * ...kid_chain[0] AKID should indicate the right CA SKID that we want.
	 *
	 * Because of cross-signing, we check all of them and accept we may get
	 * multiple (we can handle 3) CAs needed.
	 */

	for (n = 0; n < jci.count_skids; n++)
		cx->system_ops->jit_trust_query(cx, jci.skids[n].kid,
						(size_t)jci.skids[n].kid_len,
						(void *)inf);

	/* ... in case synchronous and it already finished the queries */

	*pvh = lws_get_vhost_by_name(cx, vhtag);
	if (*pvh) {
		/* hit, let's just use that then */
		lwsl_info("%s: bind to created vhost %s\n", __func__, vhtag);
		return 0;
	} else
		lwsl_err("%s: unable to bind to %s\n", __func__, vhtag);

	/* right now, nothing to offer */

	return 1;
}

int
lws_tls_jit_trust_vhost_bind(struct lws_context *cx, const char *address,
			     uint16_t port, const char *host,
			     struct lws_vhost **pvh)
{
	int n;

	lws_context_lock(cx, __func__); /* ------------------------- cx { */
	n = __lws_tls_jit_trust_vhost_bind(cx, address, port, host, pvh);
	lws_context_unlock(cx); /* ------------------------------------ } cx */

	return n;
}

/*
 * The server did not validate against the trust of the JIT Trust vhost that
 * the cache bound this connection to.  Whatever the reason (the server has
 * another chain now, or what we learned came from a handshake that was not
 * with it), that cache entry is wrong about this server: drop it, so the next
 * attempt goes back to the vhost it would have had without JIT Trust, and
 * starts over from there if that can't validate it either.  Otherwise the
 * entry would keep binding every later connection to a vhost that can't.
 *
 * If this failed handshake already taught us a new entry for the endpoint, it
 * names another vhost, and we leave it.
 */

static void
__lws_tls_jit_trust_peer_rejected(struct lws *wsi)
{
	struct lws_context *cx = wsi->a.context;
	char key[LWS_JIT_TRUST_KEY_MAX], vhtag[32];
	lws_tls_jit_cache_item_t *ci;
	size_t size;

	if (!cx->trust_cache || !wsi->a.vhost || !wsi->a.vhost->name ||
	    lws_tls_jit_trust_wsi_key(wsi, key, sizeof(key)) ||
	    lws_cache_item_get(cx->trust_cache, key, (const void **)&ci,
			       &size) ||
	    size != sizeof(*ci))
		return;

	tag_to_vh_name(vhtag, sizeof(vhtag), ci->xor_tag);
	if (strcmp(vhtag, wsi->a.vhost->name))
		return;

	lwsl_wsi_notice(wsi, "%s did not validate on %s, forgetting it",
			key, vhtag);

	lws_cache_item_remove(cx->trust_cache, key);
}

void
lws_tls_jit_trust_peer_rejected(struct lws *wsi)
{
	struct lws_context *cx = wsi->a.context;

	lws_context_lock(cx, __func__); /* ------------------------- cx { */
	__lws_tls_jit_trust_peer_rejected(wsi);
	lws_context_unlock(cx); /* ------------------------------------ } cx */
}

void
lws_tls_jit_trust_inflight_destroy(lws_tls_jit_inflight_t *inf)
{
	int n;

	for (n = 0; n < inf->ders; n++)
		lws_free_set_NULL(inf->der[n]);
	lws_dll2_remove(&inf->list);

	lws_free(inf);
}

static int
inflight_destroy(struct lws_dll2 *d, void *user)
{
	lws_tls_jit_inflight_t *inf;

	inf = lws_container_of(d, lws_tls_jit_inflight_t, list);

	lws_tls_jit_trust_inflight_destroy(inf);

	return 0;
}

void
lws_tls_jit_trust_inflight_destroy_all(struct lws_context *cx)
{
	lws_dll2_foreach_safe(&cx->jit_inflight, cx, inflight_destroy);
}

/* is any wsi still on one of the vhost's own lists? */
static int
lws_vhost_wsi_listed(struct lws_vhost *vh)
{
	int n;

	if (vh->count_bound_wsi ||
#if defined(LWS_WITH_CLIENT)
	    !lws_dll2_is_empty(&vh->dll_cli_active_conns_owner) ||
#endif
	    !lws_dll2_is_empty(&vh->vh_awaiting_socket_owner))
		return 1;

	if (vh->same_vh_protocol_owner)
		for (n = 0; n < vh->count_protocols; n++)
			if (!lws_dll2_is_empty(&vh->same_vh_protocol_owner[n]))
				return 1;

	return 0;
}

static void
unref_vh_grace_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_vhost *vh = lws_container_of(sul, struct lws_vhost,
						sul_unref);

	struct lws_context *cx = vh->context;

	lwsl_info("%s: %s\n", __func__, vh->lc.gutag);

	lws_context_lock(cx, __func__); /* ------ context { */

	/*
	 * Binding a wsi to the vhost cancels this, but a wsi that was moved
	 * off it while still on one of its lists would be left pointing into
	 * it.  That is a bug, but not one to turn into a use after free: keep
	 * the vhost another grace period and look again.
	 */
	if (lws_vhost_wsi_listed(vh)) {
		lwsl_vhost_err(vh, "unbound wsi still listed on it");
		lws_tls_jit_trust_vh_start_grace(vh);
	} else
		lws_vhost_destroy(vh);

	lws_context_unlock(cx); /* } context ------ */
}

void
lws_tls_jit_trust_vh_start_grace(struct lws_vhost *vh)
{
	lwsl_info("%s: %s: unused, grace %dms\n", __func__, vh->lc.gutag,
			vh->context->vh_idle_grace_ms);
	lws_sul_schedule(vh->context, 0, &vh->sul_unref, unref_vh_grace_cb,
			 (lws_usec_t)vh->context->vh_idle_grace_ms *
								LWS_US_PER_MS);
}

#if defined(_DEBUG)
static void
lws_tls_jit_trust_cert_info(const uint8_t *der, size_t der_len)
{
	struct lws_x509_cert *x;
	union lws_tls_cert_info_results *u;
	char p = 0, buf[192 + sizeof(*u)];

	if (lws_x509_create(&x))
		return;

	if (!lws_x509_parse_from_pem(x, der, der_len)) {

		u = (union lws_tls_cert_info_results *)buf;

		if (!lws_x509_info(x, LWS_TLS_CERT_INFO_ISSUER_NAME, u, 192)) {
			lwsl_info("ISS: %s\n", u->ns.name);
			p = 1;
		}
		if (!lws_x509_info(x, LWS_TLS_CERT_INFO_COMMON_NAME, u, 192)) {
			lwsl_info("CN: %s\n", u->ns.name);
			p = 1;
		}

		if (!p) {
			lwsl_err("%s: unable to get any info\n", __func__);
			lwsl_hexdump_err(der, der_len);
		}
	} else
		lwsl_err("%s: unable to load DER\n", __func__);

	lws_x509_destroy(&x);
}
#endif

/*
 * This processes the JIT Trust lookup results independent of the tls backend.
 */

static int
__lws_tls_jit_trust_got_cert_cb(struct lws_context *cx, void *got_opaque,
				const uint8_t *skid, size_t skid_len,
				const uint8_t *der, size_t der_len)
{
	lws_tls_jit_inflight_t *inf = (lws_tls_jit_inflight_t *)got_opaque;
	struct lws_context_creation_info info;
	lws_tls_jit_cache_item_t jci;
	struct lws_vhost *v;
	char vhtag[20];
	char hit = 0;
	int n;

	/*
	 * Before anything else, check the inf is still valid.  In the low
	 * probability but possible case it was reallocated to be a different
	 * inflight, that may cause different CA certs to apply to a connection,
	 * but since mbedtls will then validate the server cert using the wrong
	 * trusted CA, it will just cause temporary conn fail.
	 */

	lws_start_foreach_dll(struct lws_dll2 *, e, lws_dll2_get_head(&cx->jit_inflight)) {
		lws_tls_jit_inflight_t *i = lws_container_of(e,
						lws_tls_jit_inflight_t, list);
		if (i == inf) {
			hit = 1;
			break;
		}

	} lws_end_foreach_dll(e);

	if (!hit)
		/* inf has already gone */
		return 1;

	inf->refcount--;

	/*
	 * A CA cert DER is a few kB... anything wildly bigger than that is a
	 * corrupt or hostile trust store rather than something we should
	 * allocate for and hand to an ASN.1 parser.  And an empty one is no
	 * CA at all: it must not name the vhost or the cache entry, nor reach
	 * the backends as ca_mem, where no length means "load the defaults"
	 */

	if (der && (!der_len || der_len > LWS_JIT_TRUST_MAX_DER)) {
		lwsl_warn("%s: ignoring CA DER of size %u\n", __func__,
			  (unsigned int)der_len);
		der = NULL;
		der_len = 0;
	}

	/*
	 * The tag is just an opaque commutative name for the CA set, so any
	 * fixed byte order will do... but the skid pointer comes from the app's
	 * trust blob at whatever alignment the packed SKID table put it, so we
	 * must not do a naked uint32_t load through it (unaligned trap on the
	 * mcu-class targets this feature exists for, and strict-aliasing UB
	 * everywhere).
	 *
	 * Only a SKID that came back with a CA is part of the name: the cache
	 * entry records only those, and lws_tls_jit_trust_vhost_bind() looks
	 * for the vhost it regenerates from them by the cached tag.
	 */

	if (der && skid_len >= 4)
		inf->tag ^= lws_ser_ru32be(skid);

	if (der && inf->ders < (int)LWS_ARRAY_SIZE(inf->der) && inf->refcount) {
		/*
		 * We have a trusted CA, but more results coming... stash it
		 * in heap.
		 */

		inf->kid[inf->ders].kid_len = (uint8_t)((skid_len >
				     (uint8_t)sizeof(inf->kid[inf->ders].kid)) ?
				     sizeof(inf->kid[inf->ders].kid) : skid_len);
		memcpy(inf->kid[inf->ders].kid, skid,
		       inf->kid[inf->ders].kid_len);

		inf->der[inf->ders] = lws_malloc(der_len, __func__);
		if (!inf->der[inf->ders])
			return 1;
		memcpy(inf->der[inf->ders], der, der_len);
		inf->der_len[inf->ders] = der_len;
		inf->ders++;

		return 0;
	}

	/*
	 * We accept up to three valid CA, and then end the inflight early.
	 * Any further pending results are dropped, since we got all we could
	 * use.  Up to two valid CA would be held in the inflight and the other
	 * provided in the params.
	 *
	 * If we did not already fill up the inflight, keep waiting for any
	 * others expected
	 */

	if (inf->refcount && inf->ders < (int)LWS_ARRAY_SIZE(inf->der))
		return 0;

	if (!der && !inf->ders) {
		lwsl_warn("%s: no trusted CA certs matching\n", __func__);

		/*
		 * If we were regenerating a vhost from a cache entry, and none
		 * of the CAs it names can be had any more, the entry can't
		 * make a vhost: forget it rather than try again each time
		 */
		if (inf->expires)
			lws_cache_item_remove(cx->trust_cache,
					      (const char *)&inf[1]);

		goto destroy_inf;
	}

	tag_to_vh_name(vhtag, sizeof(vhtag), inf->tag);

	/*
	 * We have got at least one CA, it's all the CAs we're going to get,
	 * or that we can handle.  So we have to process and drop the inf.
	 *
	 * First let's make a cache entry with a shortish ttl, mapping the
	 * endpoint we were trying to connect to, to the SKIDs that actually
	 * had trust results.  This may come in handy later when we want to
	 * connect to the same host again, but any vhost from before has been
	 * removed... we can just ask for the specific CAs to regenerate the
	 * vhost, without having to first fail the connection attempt to get the
	 * server cert.
	 *
	 * The cache entry can be evicted at any time, so it is selfcontained.
	 * If it's also lost, we start over with the initial failing connection
	 * to figure out what we need to make it work.
	 */

	memset(&jci, 0, sizeof(jci));

	jci.xor_tag = inf->tag;

	/*
	 * The ttl runs from when we learned it from a failed connection.  A
	 * vhost regenerated from the entry keeps the entry's expiry, so it
	 * can't be kept alive by using it: only by the server showing us its
	 * chain again.
	 */

	jci.expires = inf->expires ? inf->expires :
				     lws_now_usecs() + LWS_JIT_TRUST_CACHE_TTL_US;

	/* copy the SKIDs from the inflight and params into the cache item */

	for (n = 0; n < (int)LWS_ARRAY_SIZE(inf->der); n++)
		if (inf->kid[n].kid_len)
			lws_tls_kid_copy_kid(&jci.skids[jci.count_skids++],
						&inf->kid[n]);

	/* ...the last result is only one of them if it came with a CA */

	if (der && skid_len) {
		if (skid_len > sizeof(inf->kid[0].kid))
			skid_len = sizeof(inf->kid[0].kid);
		jci.skids[jci.count_skids].kid_len = (uint8_t)skid_len;
		memcpy(jci.skids[jci.count_skids++].kid, skid, skid_len);
	}

	lwsl_info("%s: adding cache mapping %s -> %s\n", __func__,
			(const char *)&inf[1], vhtag);

	if (jci.expires > lws_now_usecs() &&
	    lws_cache_write_through(cx->trust_cache, (const char *)&inf[1],
				    (const uint8_t *)&jci, sizeof(jci),
				    jci.expires, NULL))
		lwsl_warn("%s: add to cache failed\n", __func__);

	/* is there already a vhost for this commutative-xor SKID trust? */

	if (lws_get_vhost_by_name(cx, vhtag)) {
		lwsl_info("%s: tag vhost %s already exists, skipping\n",
				__func__, vhtag);
		goto destroy_inf;
	}

	/*
	 * We only end up here when we attempted a connection to this hostname.
	 *
	 * We have the identified CA trust DER(s) to hand, let's create the
	 * necessary vhost + prepared SSL_CTX for it to use on the retry, it
	 * will be used straight away if the retry comes before the idle vhost
	 * timeout.
	 *
	 * We also use this path in the case we have the cache entry but no
	 * matching vhost already existing, to create one.
	 */

	memset(&info, 0, sizeof(info));
	info.vhost_name = vhtag;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = cx->options;

	/*
	 * Carry over the app's client TLS hardening... otherwise a server that
	 * can make us JIT-trust anything also gets to move the connection onto
	 * an SSL_CTX built with library-default protocol versions and ciphers,
	 * and with no client cert for mTLS.  The CA trust itself stays limited
	 * to the DER(s) we just fetched.
	 */

	info.alpn				= cx->tls.jit_client_policy.alpn;
	info.client_ssl_cipher_list		= cx->tls.jit_client_policy.cipher_list;
	info.client_tls_ciphers_iana		= cx->tls.jit_client_policy.ciphers_iana;
	info.client_tls_1_3_plus_cipher_list	=
				cx->tls.jit_client_policy.tls_1_3_plus_cipher_list;
	info.client_ecdh_curve			= cx->tls.jit_client_policy.ecdh_curve;
	info.client_ssl_cert_filepath		= cx->tls.jit_client_policy.cert_filepath;
	info.client_ssl_private_key_filepath	=
				cx->tls.jit_client_policy.private_key_filepath;
	info.ssl_client_options_set		= cx->tls.jit_client_policy.options_set;
	info.ssl_client_options_clear		= cx->tls.jit_client_policy.options_clear;

	/*
	 * We have to create the vhost with the first valid trusted DER...
	 * if we have a params one, use that so the rest are all from inflight
	 */

	if (der) {
		info.client_ssl_ca_mem = der;
		info.client_ssl_ca_mem_len = (unsigned int)der_len;
		n = 0;
	} else {
		info.client_ssl_ca_mem = inf->der[0];
		info.client_ssl_ca_mem_len = (unsigned int)inf->der_len[0];
		n = 1;
	}

#if defined(_DEBUG)
	lws_tls_jit_trust_cert_info(info.client_ssl_ca_mem,
				    info.client_ssl_ca_mem_len);
#endif

	info.protocols = cx->protocols_copy;

	v = lws_create_vhost(cx, &info);
	if (!v) {
		lwsl_err("%s: failed to create vh %s\n", __func__, vhtag);
		goto destroy_inf;
	}

	v->grace_after_unref = 1;
	lws_tls_jit_trust_vh_start_grace(v);

	/*
	 * Do we need to add more trusted certs from inflight?
	 */

	while (n < inf->ders && n < (int)LWS_ARRAY_SIZE(inf->der)) {

#if defined(_DEBUG)
		lws_tls_jit_trust_cert_info(inf->der[n],
					    (size_t)inf->der_len[n]);
#endif

		if (lws_tls_client_vhost_extra_cert_mem(v, inf->der[n],
						(size_t)inf->der_len[n]))
			lwsl_err("%s: add extra cert failed\n", __func__);
		n++;
	}

	lwsl_info("%s: created jitt %s -> vh %s\n", __func__,
				(const char *)&inf[1], vhtag);

destroy_inf:
	lws_tls_jit_trust_inflight_destroy(inf);

	return 0;
}

int
lws_tls_jit_trust_got_cert_cb(struct lws_context *cx, void *got_opaque,
			      const uint8_t *skid, size_t skid_len,
			      const uint8_t *der, size_t der_len)
{
	int n;

	lws_context_lock(cx, __func__); /* ------------------------- cx { */
	n = __lws_tls_jit_trust_got_cert_cb(cx, got_opaque, skid, skid_len,
					    der, der_len);
	lws_context_unlock(cx); /* ------------------------------------ } cx */

	return n;
}

/*
 * Refer to ./READMEs/README.jit-trust.md for blob layout specification
 */

int
lws_tls_jit_trust_blob_queury_skid(const void *_blob, size_t blen,
				   const uint8_t *skid, size_t skid_len,
				   const uint8_t **prpder, size_t *prder_len)
{
	const uint8_t *pskidlen, *pskids, *pder, *blob = (uint8_t *)_blob;
	size_t siz, ofs_derlen, ofs_skidlen, ofs_skid;
	const uint16_t *pderlen;
	int certs;

	/*
	 * Sanity check blob length and magic... a blob may be as small as the
	 * few CAs a device trusts, it just has to hold its own header
	 */

	if (blen < LJT_OFS_DER ||
	   lws_ser_ru32be(blob) != LWS_JIT_TRUST_MAGIC_BE ||
	   lws_ser_ru32be(blob + LJT_OFS_END) != blen) {
		lwsl_err("%s: blob not sane\n", __func__);

		return -1;
	}

	if (!skid_len)
		return 1;

	/*
	 * The sub-tables follow the DERs, and must lie inside the blob: a
	 * 16-bit DER length and an 8-bit SKID length per cert, then the SKIDs
	 */

	certs		= (int)lws_ser_ru16be(blob + LJT_OFS_32_COUNT_CERTS);
	ofs_derlen	= lws_ser_ru32be(blob + LJT_OFS_32_DERLEN);
	ofs_skidlen	= lws_ser_ru32be(blob + LJT_OFS_32_SKIDLEN);
	ofs_skid	= lws_ser_ru32be(blob + LJT_OFS_32_SKID);

	if (ofs_derlen < LJT_OFS_DER || ofs_derlen > blen ||
	    (blen - ofs_derlen) / 2 < (size_t)certs ||
	    ofs_skidlen < LJT_OFS_DER || ofs_skidlen > blen ||
	    blen - ofs_skidlen < (size_t)certs ||
	    ofs_skid < LJT_OFS_DER || ofs_skid > blen) {
		lwsl_err("%s: blob tables not sane\n", __func__);

		return -1;
	}

	/* point into the various sub-tables */

	pderlen		= (uint16_t *)(blob + ofs_derlen);
	pskidlen	= blob + ofs_skidlen;
	pskids		= blob + ofs_skid;
	pder		= blob + LJT_OFS_DER;

	/* check each cert SKID in turn, return the DER if found */

	while (certs--) {

		/*
		 * paranoia / sanity... these must be "are the bytes we are
		 * about to consume inside the blob", not just "is the cursor
		 * inside the blob": the memcmp() below reads skid_len (up to
		 * 20) bytes from pskids, and *pskidlen is attacker-chosen
		 * content of the same untrusted blob, so it bounds nothing.
		 */

		if (pskids + skid_len > blob + blen) {
			assert(0);
			break;
		}
		if (pder >= blob + blen) {
			assert(0);
			break;
		}
		if (pskidlen + 1 > blob + blen) {
			assert(0);
			break;
		}
		if ((const uint8_t *)pderlen + 2 > blob + blen) {
			assert(0);
			break;
		}

		/* we will accept to match on truncated SKIDs */

		if (*pskidlen >= skid_len &&
		    !memcmp(skid, pskids, skid_len)) {
			/*
			 * We found a trusted CA cert of the right SKID... but
			 * the caller only hears about it if its DER is really
			 * there: consumers take a set *prpder as "found"
			 */
			siz = lws_ser_ru16be((uint8_t *)pderlen);

			if (!siz ||
			    siz >= blen - lws_ptr_diff_size_t(pder, blob))
				break;

			*prpder = pder;
			*prder_len = siz;

			return 0;
		}

		pder += lws_ser_ru16be((uint8_t *)pderlen);
		pskids += *pskidlen;
		pderlen++;
		if (pderlen >= (const uint16_t *)(blob + blen))
			break;

		pskidlen++;
	}

	return 1;
}
