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
 * cose_sign handling
 *
 * Validation:
 *
 *  - we put all our pieces and results in an lwsac in the parse state object
 *
 *  - we collect pieces needed for sig validation into lwsac elements
 *
 *  - we go through each signature making discrete results in the lwsac for
 *    the user code to assess
 */

#include "private-lib-core.h"
#include "private-lib-cose.h"

const uint8_t *sig_mctx[] = { (uint8_t *)"",
				    (uint8_t *)"\x85\x69""Signature",
				    (uint8_t *)"\x84\x6a""Signature1",
				    (uint8_t *)"\x85\x6f""CounterSignature",
				    (uint8_t *)"\x84\x63""MAC",
				    (uint8_t *)"\x84\x64""MAC0",
};
uint8_t sig_mctx_len[] = { 0, 11, 12, 17, 5, 6 };

struct alg_names {
	const char	*name;
	cose_param_t	alg;
} alg_names[] = {
	{ "ES256",	LWSCOSE_WKAECDSA_ALG_ES256 },
	{ "ES384", 	LWSCOSE_WKAECDSA_ALG_ES384 },
	{ "ES512",	LWSCOSE_WKAECDSA_ALG_ES512 },
	{ "EdDSA",	LWSCOSE_WKAEDDSA_ALG_EDDSA },
	{ "HS256_64", 	LWSCOSE_WKAHMAC_256_64 },
	{ "HS256", 	LWSCOSE_WKAHMAC_256_256 },
	{ "HS384", 	LWSCOSE_WKAHMAC_384_384 },
	{ "HS512", 	LWSCOSE_WKAHMAC_512_512 },
	{ "RS256", 	LWSCOSE_WKARSA_ALG_RS256 },
	{ "RS384", 	LWSCOSE_WKARSA_ALG_RS384 },
	{ "RS512", 	LWSCOSE_WKARSA_ALG_RS512 },
};

/*
 * The Sig_structure plaintext is new temp CBOR made up from pieces from the
 * cose_sign, cose_signature, and payload in a specific order
 *
 *  tstr     context string
 *  bstr     0-len or protected body headers
 *  bstr     (Missing for sign1) 0-len or protected signer headers
 *  bstr     0-len or protected application part
 *  bstr     the payload
 *
 * We are getting CBOR with an optional outer tag and then an array of exactly
 * 4 items in a fixed order
 *
 * [
 *   protected headers: bstr containing a map (captured as CBOR in cps->ph[])
 *   unprotected: map: for sign1, eg, the alg (!?), the kid
 *   payload: bstr
 *   if sign: signatures: [ cose_signature struct array,
 *   			    each is a 3-element array
 *     [
 *       protected: bstr containing a map: (eg, the alg) (captured as CBOR)
 *       unprotected: map: (eg, the kid)
 *       signature:  bstr
 *     ]
 *   if sign1: bstr containing signature
 * ]
 *
 * The last signatures field may be an array of signatures, or a single
 * cose_signature object for cose_sign1.
 *
 * For cose_sign1, we know the signature alg before the payload and can do it
 * in a single pass.  But for sign, we do not know the signature algs until
 * after the payload, which is an unfortunate oversight in cose_sign, meaning we
 * cannot hash the payload one or more ways in a single pass.
 */

#if defined(VERBOSE)
const char *cose_sections[] = {
	"ST_UNKNOWN",

	"ST_OUTER_PROTECTED",
	"ST_OUTER_UNPROTECTED",
	"ST_OUTER_PAYLOAD",
	"ST_OUTER_SIGN1_SIGNATURE",

	"ST_OUTER_SIGN_SIGARRAY",

	"ST_OUTER_MACTAG",

	"ST_INNER_PROTECTED",
	"ST_INNER_UNPROTECTED",
	"ST_INNER_SIGNATURE",

	"ST_INNER_EXCESS",
};
#endif

const char *
lws_cose_alg_to_name(cose_param_t alg)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(alg_names); n++)
		if (alg_names[n].alg == alg)
			return alg_names[n].name;

	return "unknown_alg";
}

cose_param_t
lws_cose_name_to_alg(const char *name)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(alg_names); n++)
		if (!strcmp(alg_names[n].name, name))
			return alg_names[n].alg;

	return 0;
}

static size_t
bstr_len(uint8_t *t, size_t buflen, uint8_t opcode, uint64_t len)
{
	uint8_t *ot = t;

	if (buflen < 9)
		return 0;

	if (len < 24) {
		*t = (uint8_t)(opcode | len);

		return 1;
	}
	if (len < 256) {
		*t++ = opcode | LWS_CBOR_1;
		goto b;
	}
	if (len < 65536) {
		*t++ = opcode | LWS_CBOR_2;
		goto b1;
	}
	if (len < 0xffffffffu) {
		*t++ = opcode | LWS_CBOR_4;
		goto b2;
	}

	*t++ = opcode | LWS_CBOR_8;

	*t++ = (uint8_t)(len >> 56);
	*t++ = (uint8_t)(len >> 48);
	*t++ = (uint8_t)(len >> 40);
	*t++ = (uint8_t)(len >> 32);

b2:
	*t++ = (uint8_t)(len >> 24);
	*t++ = (uint8_t)(len >> 16);
b1:
	*t++ = (uint8_t)(len >> 8);
b:
	*t++ = (uint8_t)len;

	return lws_ptr_diff_size_t(t, ot);
}

/*
 * The alg list head as an alg pointer, NULL if the list is empty.
 *
 * The !alg checks at the call sites rely on this returning NULL for an
 * empty list; that must not be done with a bare container_of() on the
 * list head, which is only NULL while list is the first member of
 * lws_cose_sig_alg_t.
 */
static lws_cose_sig_alg_t *
alg_get_head(struct lws_cose_validate_context *cps)
{
	struct lws_dll2 *d = lws_dll2_get_head(&cps->algs);

	return d ? lws_container_of(d, lws_cose_sig_alg_t, list) : NULL;
}

/*
 * Accumulate a piece of the signature bstr.
 *
 * The bstr header length can't be trusted to bound this: for an
 * indefinite-length bstr lecp never sets item.u.u64, and there is no limit on
 * how many fragments follow.  So bound every append by the room actually left.
 */

static int
sig_agg(struct lws_cose_validate_context *cps, struct lecp_ctx *ctx)
{
	if (cps->sig_agg_pos + ctx->npos > sizeof(cps->sig_agg)) {
		lwsl_notice("%s: oversize signature\n", __func__);

		return 1;
	}

	memcpy(cps->sig_agg + cps->sig_agg_pos, ctx->buf, ctx->npos);
	cps->sig_agg_pos += ctx->npos;

	return 0;
}

/*
 * How much of the start of a captured protected bucket is the bucket's own
 * bstr header?  The raw capture holds the bstr exactly as it was serialized,
 * which is what has to go into the Sig_structure, but the header has to come
 * off again before the map inside can be handed back to the parser.
 *
 * Returns 0 if it doesn't start with a definite-length bstr header, eg, the
 * unprotected bucket, whose map header is not part of the capture.
 */

static size_t
bstr_hdr_len(const uint8_t *p, size_t len)
{
	uint8_t u;

	if (!len || ((*p) & LWS_CBOR_MAJTYP_MASK) != LWS_CBOR_MAJTYP_BSTR)
		return 0;

	u = (*p) & LWS_CBOR_SUBMASK;

	if (u < LWS_CBOR_1)
		return 1;

	switch (u) {
	case LWS_CBOR_1:
		return 2;
	case LWS_CBOR_2:
		return 3;
	case LWS_CBOR_4:
		return 5;
	case LWS_CBOR_8:
		return 9;
	}

	return 0; /* indefinite or reserved, not something we can strip */
}

/*
 * The captured bucket as it has to appear in the Sig_structure.
 *
 * RFC9052 4.4: an empty protected bucket appears there as a zero-length bstr.
 * Objects in the wild (and the cose-wg vectors) serialize the empty bucket
 * either as h'' or as h'a0' (a bstr holding an empty map), but sign h'' for
 * both, so both have to normalize here.  Anything else goes in exactly as it
 * was serialized, which is what the raw capture holds... rebuilding a
 * canonical bstr header from the content length instead mis-hashes a peer's
 * long-form header and drops a one-byte bucket on the floor.
 */

static const uint8_t *
sig_bucket(const uint8_t *p, size_t *s)
{
	static const uint8_t empty = LWS_CBOR_MAJTYP_BSTR; /* ie, h'' */
	size_t hl = bstr_hdr_len(p, *s);

	if (hl > *s)
		/* malformed, the parse of it will have bailed already */
		return p;

	if (*s - hl == 0 ||
	    (*s - hl == 1 && p[hl] == LWS_CBOR_MAJTYP_MAP /* h'a0' */)) {
		*s = 1;

		return &empty;
	}

	return p;
}

/*
 * Hand the map inside a captured bucket back to the parser as a subtree.
 *
 * lecp_parse_subtree() is inside a pushed level, so it cannot return 0 to mean
 * "the subtree was complete"... a truncated subtree, eg, a map that declares
 * more pairs than it carries, used to be indistinguishable from a complete
 * one.  It leaves the levels it pushed live above its barrier, and the rest of
 * the object is then parsed at a path depth that matches none of the tests in
 * the callback: the object "validates" to an empty results list.  Confirm the
 * parser came back to exactly the state it went in at, and fail the whole
 * validation if it did not.
 */

static int
parse_bucket(struct lws_cose_validate_context *cps, uint8_t *p, size_t s)
{
	struct lecp_ctx *ctx = &cps->ctx;
	uint8_t sp = ctx->sp;
	uint8_t ppos = ctx->pst[ctx->pst_sp].ppos;
	size_t hl = bstr_hdr_len(p, s);
	int n;

	if (hl > s)
		return 1;

	if (hl == s)
		/* a zero-length bucket, ie, no params, nothing to parse */
		return 0;

	cps->sub = 1;
	n = lecp_parse_subtree(ctx, p + hl, s - hl);
	cps->sub = 0;

	if (n != LECP_CONTINUE)
		return 1;

	if (ctx->sp != sp) {
		/*
		 * The subtree did not complete inside the bucket bytes: the
		 * levels it pushed are still live above its barrier, and
		 * lwcp_completed()'s walk will stop at that barrier forever
		 * after, ie, the rest of the object is parsed at a depth the
		 * state machine below matches nothing at
		 */

		lwsl_notice("%s: incomplete bucket\n", __func__);

		return 1;
	}

	/*
	 * A bstr map key inside the bucket appends itself to the shared path,
	 * and at the subtree's own base level lecp_parse_map_is_key() is
	 * looking at the parent level of the *outer* parse, across the
	 * barrier, so the path can grow for something that is not a map key at
	 * all.  Either way it is not the outer parse's path, put it back.
	 */

	ctx->pst[ctx->pst_sp].ppos = ppos;
	ctx->path[ppos] = '\0';

	return 0;
}

static int
apply_external(struct lws_cose_validate_context *cps)
{
	lws_cose_sig_alg_t *alg;
	uint8_t t[9];

	alg = alg_get_head(cps);
	if (!alg)
		/* expected if no key */
		return 0;

	/* get the external payload first, if any indicated */

	if (cps->info.ext_len) {
		lws_cose_sig_ext_pay_t ex;
		size_t s;

		s = bstr_len(t, sizeof(t), LWS_CBOR_MAJTYP_BSTR,
			     cps->info.ext_len);
		if (lws_cose_val_alg_hash(alg, t, s))
			return 1;

		memset(&ex, 0, sizeof(ex));
		ex.cps = cps;

		do {
			int n;

			ex.xl = 0;
			n = cps->info.ext_cb(&ex);

			if (ex.xl &&
			    lws_cose_val_alg_hash(alg, ex.ext, ex.xl))
				return 1;

			if (n == LCOSESIGEXTCB_RET_ERROR)
				return 1;

			if (n == LCOSESIGEXTCB_RET_FINISHED)
				break;
		} while (1);
	}

	return 0;
}

static int
create_alg(struct lecp_ctx *ctx, struct lws_cose_validate_context *cps)
{
	lws_cose_validate_param_stack_t *sl = &cps->st[cps->sp], *sl0 = &cps->st[0];
	lws_cose_validate_res_t *res;
	lws_cose_sig_alg_t *alg;
	lws_cose_key_t *ck;
	const uint8_t *p;
	size_t s;

	/*
	 * Each of these costs a hash of the whole (stashed) payload and a
	 * public key verify, and each also creates a result object that lives
	 * until the validation context is destroyed... the object chooses how
	 * many of them there are, so the cost is quadratic in its size unless
	 * we refuse to go past a sane number
	 */

	if (++cps->sigs > MAX_COSE_SIGNATURES) {
		lwsl_warn("%s: too many signatures\n", __func__);

		return 1;
	}

	/* with sign1, we can hash the payload in a
	 * single pass */

	ck = lws_cose_key_from_set(cps->info.keyset, sl->kid.buf, sl->kid.len);
	if (!ck) {
		lwsl_info("%s: no key\n", __func__);
		goto no_key_or_alg;
	}

	// lwsl_notice("%s: cps->alg %d\n", __func__, (int)cps->alg);

	/*
	 * sl0->alg is the alg for the thing we are validating: for cose_sign
	 * the per-signature state IS sl0 (sp stays 0 inside the signature
	 * array) and it is reset at the start of every cose_signature, so each
	 * signature gets its own alg.  For cose_mac, sl is the recipient and
	 * its alg is a key-management alg (eg, "direct"), not the MAC alg,
	 * which only exists at the body level.
	 */

	alg = lws_cose_val_alg_create(cps->info.cx, ck, sl0->alg,
				      LWSCOSE_WKKO_VERIFY);
	if (!alg) {
		lwsl_info("%s: no alg\n", __func__);

no_key_or_alg:
		/*
		 * We can't create the alg then, so we can't normally
		 * create a result object.  Create one especially for this
		 * case and continue on
		 */

		res = lws_zalloc(sizeof(*res), __func__);
		if (res) {
			res->result = -1001;

			lws_dll2_add_tail(&res->list, &cps->results);
		}

		return 0;
	}

	lws_dll2_add_tail(&alg->list, &cps->algs);

	/*
	 * Hash step 1: The first hash content depends on
	 *              sign/sign1/csign/mac/mac0 constant bstr
	 */

	if (lws_cose_val_alg_hash(alg, sig_mctx[cps->info.sigtype],
			       sig_mctx_len[cps->info.sigtype]))
		goto bail;

	/*
	 * Hash step 2: A zero-length bstr, or a copy of the
	 *              OUTER protected headers
	 */

	s = (size_t)sl0->ph_pos[0];
	p = sig_bucket(sl0->ph[0] + 3, &s);

	if (lws_cose_val_alg_hash(alg, p, s))
		goto bail;

	/*
	 * Hash step 3: Protected signer headers (Elided for sign1)
	 */

	if (cps->info.sigtype == SIGTYPE_MULTI) {
		s = (size_t)sl->ph_pos[2];
		p = sig_bucket(sl->ph[2] + 3, &s);

		if (lws_cose_val_alg_hash(alg, p, s))
			goto bail;
	}

	/* Hash step 4: bstr for applictation protected pieces
	 *              empty for now
	 */

	if (!cps->info.ext_len) { /* ie, if no app data */
		uint8_t u = LWS_CBOR_MAJTYP_BSTR;
		if (lws_cose_val_alg_hash(alg, &u, 1))
			goto bail;
	}

	/*
	 * The final part is the payload in its own bstr, as
	 * we get it if sign1, else replayed from a cache in heap
	 */

	if (cps->info.sigtype == SIGTYPE_SINGLE)
		return 0;

	if (!cps->payload_stash) {
		lwsl_notice("%s: no payload stash\n", __func__);
		goto bail;
	}

	apply_external(cps);

	if (lws_cose_val_alg_hash(alg, cps->payload_stash, cps->payload_pos))
		goto bail;

	lws_cose_val_alg_destroy(cps, &alg, (const uint8_t *)cps->sig_agg,
				 cps->sig_agg_pos);

	return 0;

bail:
	return 1;
}

#if defined(VERBOSE)
static const char * const reason_names[] = {
	"LECPCB_CONSTRUCTED",
	"LECPCB_DESTRUCTED",
	"LECPCB_START",
	"LECPCB_COMPLETE",
	"LECPCB_FAILED",
	"LECPCB_PAIR_NAME",
	"LECPCB_VAL_TRUE",
	"LECPCB_VAL_FALSE",
	"LECPCB_VAL_NULL",
	"LECPCB_VAL_NUM_INT",
	"LECPCB_VAL_RESERVED", /* float in lejp */
	"LECPCB_VAL_STR_START",
	"LECPCB_VAL_STR_CHUNK",
	"LECPCB_VAL_STR_END",
	"LECPCB_ARRAY_START",
	"LECPCB_ARRAY_END",
	"LECPCB_OBJECT_START",
	"LECPCB_OBJECT_END",
	"LECPCB_TAG_START",
	"LECPCB_TAG_END",
	"LECPCB_VAL_NUM_UINT",
	"LECPCB_VAL_UNDEFINED",
	"LECPCB_VAL_FLOAT16",
	"LECPCB_VAL_FLOAT32",
	"LECPCB_VAL_FLOAT64",
	"LECPCB_VAL_SIMPLE",
	"LECPCB_VAL_BLOB_START",
	"LECPCB_VAL_BLOB_CHUNK",
	"LECPCB_VAL_BLOB_END",
	"LECPCB_ARRAY_ITEM_START",
	"LECPCB_ARRAY_ITEM_END",
	"LECPCB_LITERAL_CBOR"
};
#endif

static int
ph_index(struct lws_cose_validate_context *cps)
{
	switch (cps->tli) {
	case ST_OUTER_PROTECTED:
		return 0;
	case ST_OUTER_UNPROTECTED:
		return 1;
	case ST_INNER_PROTECTED:
		return 2;
	case ST_INNER_UNPROTECTED:
		return 3;
	}

	assert(0);
	return 0;
}

static signed char
cb_cose_sig(struct lecp_ctx *ctx, char reason)
{
	struct lws_cose_validate_context *cps =
			(struct lws_cose_validate_context *)ctx->user;
	lws_cose_validate_param_stack_t *sl;
	struct lws_gencrypto_keyelem *ke;
	lws_cose_sig_alg_t *alg;
	uint8_t t[9];
	size_t s;
	int hi;

#if defined(VERBOSE)
	lwsl_notice("%s: %s, tli %s, sub %d, ppos %d, sp %d\n", __func__,
			reason_names[reason & 0x1f], cose_sections[cps->tli],
			cps->sub, ctx->pst[ctx->pst_sp].ppos, cps->sp);
#endif

	switch (reason) {
	case LECPCB_CONSTRUCTED:
		break;

	case LECPCB_TAG_START:

		lwsl_info("%s: tag sigtype %d\n", __func__, cps->info.sigtype);

		switch (cps->info.sigtype) {
		default:
			assert(0);
			break;
		case SIGTYPE_UNKNOWN:
			/* it means use the tag value to set the type */
			switch (ctx->item.u.u64) {
			case LWSCOAP_CONTENTFORMAT_COSE_SIGN:
				cps->info.sigtype = SIGTYPE_MULTI;
				break;
			case LWSCOAP_CONTENTFORMAT_COSE_SIGN1:
				cps->info.sigtype = SIGTYPE_SINGLE;
				break;
//			case LWSCOAP_CONTENTFORMAT_COSE_SIGN__:
//				cps->info.sigtype = SIGTYPE_COUNTERSIGNED;
//				break;
			case LWSCOAP_CONTENTFORMAT_COSE_MAC0:
				cps->info.sigtype = SIGTYPE_MAC0;
				break;
			case LWSCOAP_CONTENTFORMAT_COSE_MAC:
				cps->info.sigtype = SIGTYPE_MAC;
				break;
			default:
				goto unexpected_tag_l;
			}
			break;
		case SIGTYPE_MULTI:
			if (ctx->item.u.u64 != LWSCOAP_CONTENTFORMAT_COSE_SIGN)
				goto unexpected_tag_l;
			break;
		case SIGTYPE_SINGLE:
			if (ctx->item.u.u64 != LWSCOAP_CONTENTFORMAT_COSE_SIGN1)
				goto unexpected_tag_l;
			break;
		case SIGTYPE_COUNTERSIGNED:
			if (ctx->item.u.u64 != LWSCOAP_CONTENTFORMAT_COSE_SIGN)
				goto unexpected_tag_l;
			break;
		case SIGTYPE_MAC0:
			if (ctx->item.u.u64 != LWSCOAP_CONTENTFORMAT_COSE_MAC0)
				goto unexpected_tag_l;
			break;
		case SIGTYPE_MAC:
			if (ctx->item.u.u64 != LWSCOAP_CONTENTFORMAT_COSE_MAC)
				goto unexpected_tag_l;
			break;
		}

		cps->depth++;
		break;

	case LECPCB_ARRAY_START:

		if (cps->sub || cps->tli != ST_OUTER_PROTECTED ||
		    ctx->pst[ctx->pst_sp].ppos != 2)
			break;

		/*
		 * The outer array has just opened, and its first item is the
		 * protected bucket.  Start the raw capture now, before the
		 * bucket's first byte: switching it on from inside the item's
		 * own ARRAY_ITEM_START is a byte late, which loses the bstr
		 * header of a canonical bucket and, for a long-form one, keeps
		 * part of that header as if it were bucket content.
		 */

		lecp_parse_report_raw(ctx, 1);
		break;

	case LECPCB_ARRAY_ITEM_START:

		if (cps->sub)
			break;

		if (ctx->pst[ctx->pst_sp].ppos == 4 ||
		    ctx->pst[ctx->pst_sp].ppos == 6) {

			if (ctx->pst[ctx->pst_sp].ppos == 4) {
				/*
				 * A new cose_signature is starting.  Rearm the
				 * signer state: without this only the first
				 * signature of a cose_sign was ever parsed
				 * (tli stuck at ST_INNER_EXCESS), and each
				 * signature must use its own alg and kid
				 * rather than inherit the previous one's.
				 */
				if (cps->tli == ST_INNER_EXCESS)
					cps->tli = ST_INNER_PROTECTED;

				if (cps->tli == ST_INNER_PROTECTED) {
					sl = &cps->st[cps->sp];
					sl->alg = 0;
					sl->alg_prot = 0;
					if (sl->kid.buf) {
						lws_free(sl->kid.buf);
						sl->kid.buf = NULL;
						sl->kid.len = 0;
					}
				}
			}

			switch (cps->tli) {
			case ST_INNER_UNPROTECTED:
			case ST_INNER_PROTECTED:
				hi = ph_index(cps);
				sl = &cps->st[cps->sp];
				sl->ph_pos[hi] = 0;
				lecp_parse_report_raw(ctx, 1);
				break;
			default:
				break;
			}
			break;
		}

		if (ctx->pst[ctx->pst_sp].ppos != 2)
			break;

		switch (cps->tli) {
		case ST_OUTER_UNPROTECTED:
		case ST_OUTER_PROTECTED:
			/*
			 * Holy type confusion, Batman... this is a CBOR bstr
			 * containing valid CBOR that must also be parsed as
			 * part of the containing array... we need to collect
			 * it anyway since it is part of the signing plaintext
			 * in bstr form, let's get it and then parse it at the
			 * END of the bstr.
			 */
			lecp_parse_report_raw(ctx, 1);
			break;

		case ST_OUTER_PAYLOAD:
			if (cps->info.sigtype != SIGTYPE_SINGLE)
				break;

			if (create_alg(ctx, cps))
				goto bail;

			break;

		case ST_OUTER_SIGN_SIGARRAY:
			cps->tli = ST_INNER_PROTECTED;
			break;
		}
		break;

	case LECPCB_ARRAY_ITEM_END:

		if (cps->sub)
			break;

		if (ctx->pst[ctx->pst_sp].ppos == 2) {
			sl = &cps->st[cps->sp];
			switch (cps->tli) {
			case ST_OUTER_UNPROTECTED:
				/*
				 * The outer unprotected map is parsed inline,
				 * we don't want to reparse the raw capture of
				 * it... but we must still stop capturing, or
				 * every later byte (the payload!) keeps being
				 * appended into the protected header buffers
				 */
				lecp_parse_report_raw(ctx, 0);
				break;

			case ST_OUTER_PROTECTED:
				lecp_parse_report_raw(ctx, 0);

				hi = ph_index(cps);

				if (!sl->ph_pos[hi] || cps->sub)
					break;

				if (parse_bucket(cps, sl->ph[hi] + 3,
						 (size_t)sl->ph_pos[hi]))
					goto bail;
				break;

			case ST_OUTER_PAYLOAD:
				switch (cps->info.sigtype) {
				case SIGTYPE_MULTI:
					cps->tli = ST_OUTER_SIGN_SIGARRAY - 1;
					break;
				case SIGTYPE_MAC:
				case SIGTYPE_MAC0:
					cps->tli = ST_OUTER_MACTAG - 1;
					break;
				case SIGTYPE_COUNTERSIGNED:
					break;
				default:
					break;
				}
				break;

			case ST_OUTER_SIGN1_SIGNATURE:
			case ST_OUTER_MACTAG:
				cps->sp++;
				cps->tli = ST_INNER_PROTECTED - 1;
				break;

			case ST_INNER_UNPROTECTED:
			case ST_INNER_PROTECTED:
				break;

			case ST_INNER_EXCESS:
			case ST_OUTER_SIGN_SIGARRAY:
				cps->tli--; /* so no change */
				break;
			}
			if (!cps->sub)
				cps->tli++;
		}

		if (ctx->pst[ctx->pst_sp].ppos >= 4) {

			switch (cps->tli) {
			case ST_INNER_UNPROTECTED:
			case ST_INNER_PROTECTED:

				hi = ph_index(cps);
				sl = &cps->st[cps->sp];
				lecp_parse_report_raw(ctx, 0);

				if (!sl->ph_pos[hi] || cps->sub) {
					if (!cps->sub)
						cps->tli++;
					break;
				}

				/*
				 * The capture holds the bucket as it was
				 * serialized, ie, including its own bstr
				 * header... parse_bucket() takes the header
				 * off again to get at the map inside, we must
				 * leave the capture itself alone since it is
				 * also the Sig_structure piece
				 */

				if (parse_bucket(cps, sl->ph[hi] + 3,
						 (size_t)sl->ph_pos[hi]))
					goto bail;

				cps->tli++;
				break;

			case ST_INNER_SIGNATURE:
				if (cps->info.sigtype == SIGTYPE_MAC) {
					// lwsl_err("Y: alg %d\n", (int)cps->alg);
					if (create_alg(ctx, cps))
						goto bail;
				}
				cps->tli++;
				break;
			default:
				break;
			}
		}

		break;

	case LECPCB_VAL_NUM_INT:
	case LECPCB_VAL_NUM_UINT:
		switch (cps->tli) {
		case ST_INNER_PROTECTED:
		case ST_INNER_UNPROTECTED:
		case ST_INNER_SIGNATURE:
		case ST_OUTER_PROTECTED:
		case ST_OUTER_UNPROTECTED:
			if (lecp_parse_map_is_key(ctx)) {
				cps->map_key = ctx->item.u.i64;
				// lwsl_notice("%s: key %d\n", __func__, (int)cps->map_key);
				break;
			}

			// lwsl_notice("%s: key %d val %d\n", __func__, (int)cps->map_key, (int)ctx->item.u.i64);

			if (cps->map_key == LWSCOSE_WKL_ALG) {
				int prot = cps->tli == ST_OUTER_PROTECTED ||
					   cps->tli == ST_INNER_PROTECTED;

				sl = &cps->st[cps->sp];
				cps->map_key = 0;

				/*
				 * RFC9052 3.1: the unprotected bucket is not
				 * covered by the signature, so an alg from
				 * there must never replace one that came from
				 * the protected bucket... otherwise anybody can
				 * downgrade the alg of an otherwise valid
				 * object (eg, HS512 -> HS256_64, or an ECDSA
				 * object into an HMAC one).  We still accept an
				 * unprotected alg if the protected bucket did
				 * not give us one, as RFC9052's own test
				 * vectors require.
				 */

				if (!prot && sl->alg_prot)
					break;

				sl->alg = ctx->item.u.i64;
				sl->alg_prot = (char)prot;
				break;
			}
			break;
		}
		break;

	case LECPCB_VAL_STR_END:
		switch (cps->tli) {
		case ST_OUTER_UNPROTECTED:
			break;
		}
		break;

	case LECPCB_VAL_BLOB_START:

		if (cps->tli == ST_OUTER_SIGN1_SIGNATURE ||
		    cps->tli == ST_INNER_SIGNATURE) {
			/*
			 * Reset unconditionally, and don't look at
			 * item.u.u64 at all: lecp does not set it for a
			 * zero-length or an indefinite-length bstr, so what is
			 * in there is whatever the previous item left (eg, the
			 * alg -7 from the protected bucket, which as a u64
			 * rejected a legal empty signature).  sig_agg() bounds
			 * the accumulate by the room actually left.
			 */
			cps->sig_agg_pos = 0;
			break;
		}

		if (cps->tli != ST_OUTER_PAYLOAD)
			break;

		if (apply_external(cps)) {
			lwsl_notice("%s: ext\n", __func__);
			goto bail;
		}

		s = bstr_len(t, sizeof(t), LWS_CBOR_MAJTYP_BSTR,
			     ctx->item.u.u64);

		if (cps->info.sigtype == SIGTYPE_SINGLE) {
			alg = alg_get_head(cps);
			if (!alg)
				/* expected if no key */
				break;
			if (lws_cose_val_alg_hash(alg, t, s)) {
				lwsl_notice("%s: hash failed\n", __func__);
				goto bail;
			}

			break;
		}

		/*
		 * We are about to allocate on the strength of a length the
		 * attacker wrote in the bstr header, before a single payload
		 * byte has arrived... cap it.  And the payload slot must hold
		 * exactly one bstr: a second one would otherwise silently
		 * replace (and leak) the buffer we already have.
		 */

		if (cps->payload_stash) {
			lwsl_notice("%s: extra payload bstr\n", __func__);
			goto bail;
		}

		if (ctx->item.u.u64 > MAX_STASHED_PAYLOAD) {
			lwsl_notice("%s: payload len %llu too big\n", __func__,
				    (unsigned long long)ctx->item.u.u64);
			goto bail;
		}

		cps->payload_stash_size = (size_t)(ctx->item.u.u64 + s);
		cps->payload_stash = lws_malloc(cps->payload_stash_size,
							__func__);
		if (!cps->payload_stash) {
			lwsl_notice("%s: oom\n", __func__);
			goto bail;
		}

		memcpy(cps->payload_stash, t, s);
		cps->payload_pos = s;

		break;

	case LECPCB_VAL_BLOB_CHUNK:
		switch (cps->tli) {
		case ST_OUTER_PAYLOAD:

			if (cps->info.pay_cb && ctx->npos)
				cps->info.pay_cb(cps, cps->info.pay_opaque,
						 (uint8_t *)ctx->buf, ctx->npos);

			if (cps->payload_stash) {
				if (cps->payload_pos + ctx->npos >
					cps->payload_stash_size)
					goto bail;
				memcpy(cps->payload_stash + cps->payload_pos,
						ctx->buf, ctx->npos);
				cps->payload_pos += ctx->npos;
				break;
			}
			alg = alg_get_head(cps);
			if (!alg)
				/* expected if no key */
				break;
			if (ctx->npos &&
			    lws_cose_val_alg_hash(alg, (uint8_t *)ctx->buf,
					      ctx->npos)) {
				lwsl_notice("%s: chunk fail\n", __func__);
				goto bail;
			}
			break;
		case ST_INNER_SIGNATURE:
		case ST_OUTER_SIGN1_SIGNATURE:
			/* the sig is big compared to ctx->buf... we need to
			 * stash it then */
			if (sig_agg(cps, ctx))
				goto bail;
			break;
		}
		break;

	case LECPCB_VAL_BLOB_END:
		switch (cps->tli) {

		case ST_INNER_SIGNATURE:
			if (cps->info.sigtype == SIGTYPE_MULTI) {
				if (sig_agg(cps, ctx))
					goto bail;
				// lwsl_err("Y: alg %d\n", (int)cps->alg);
				if (create_alg(ctx, cps))
					goto bail;
				break;
			}
			if (cps->info.sigtype != SIGTYPE_MAC)
				break;
			/* fallthru */
		case ST_OUTER_PROTECTED:
		case ST_OUTER_UNPROTECTED:
		case ST_INNER_PROTECTED:
		case ST_INNER_UNPROTECTED:
			if (cps->map_key == LWSCOSE_WKL_KID) {
				sl = &cps->st[cps->sp];
				ke = &sl->kid;
				if (ke->buf)
					lws_free(ke->buf);
				ke->buf = lws_malloc(ctx->npos, __func__);
				if (!ke->buf)
					goto bail;
				ke->len = ctx->npos;
				memcpy(ke->buf, ctx->buf, ctx->npos);
				cps->map_key = 0;
			}
			break;

		case ST_OUTER_PAYLOAD:
			if (cps->info.pay_cb && ctx->npos)
				cps->info.pay_cb(cps, cps->info.pay_opaque,
						 (uint8_t *)ctx->buf, ctx->npos);
			if (cps->payload_stash) {
				if (cps->payload_pos + ctx->npos >
					cps->payload_stash_size)
					goto bail;
				memcpy(cps->payload_stash + cps->payload_pos,
						ctx->buf, ctx->npos);
				cps->payload_pos += ctx->npos;
				break;
			}
			alg = alg_get_head(cps);
			if (!alg)
				/* expected if no key */
				break;

			if (ctx->npos &&
			    lws_cose_val_alg_hash(alg, (uint8_t *)ctx->buf,
					      ctx->npos))
				goto bail;
			break;

		case ST_OUTER_SIGN1_SIGNATURE:
			if (cps->info.sigtype == SIGTYPE_MULTI)
				break;

			if (sig_agg(cps, ctx))
				goto bail;

			alg = alg_get_head(cps);
			if (alg)
				lws_cose_val_alg_destroy(cps, &alg,
							 cps->sig_agg,
							 cps->sig_agg_pos);
			break;

		case ST_OUTER_MACTAG:
			if (cps->mac_pos + ctx->npos > sizeof(cps->mac))
				goto bail;
			memcpy(cps->mac + cps->mac_pos, ctx->buf, ctx->npos);
			cps->mac_pos += ctx->npos;

			if (cps->info.sigtype == SIGTYPE_MAC0) {
				if (create_alg(ctx, cps))
					goto bail;
			}

			break;
		}
		break;

	case LECPCB_LITERAL_CBOR:
		/* only used for protected headers */
		switch (cps->tli) {
		case ST_INNER_PROTECTED:
		case ST_OUTER_PROTECTED:
		case ST_INNER_UNPROTECTED:
		case ST_OUTER_UNPROTECTED:
			sl = &cps->st[cps->sp];
			hi = ph_index(cps);
			if (sl->ph_pos[hi] + 3 + ctx->cbor_len >
					(int)sizeof(sl->ph[hi]) - 3)
				/* more protected cbor than we can handle */
				goto bail;
			memcpy(sl->ph[hi] + 3 + sl->ph_pos[hi], ctx->cbor,
			       ctx->cbor_len);
			sl->ph_pos[hi] += ctx->cbor_len;
			break;
		}
	}

	return 0;

unexpected_tag_l:
	lwsl_warn("%s: unexpected tag %d\n", __func__,
			(int)ctx->item.u.u64);
	goto bail;

bail:

	return -1;
}

struct lws_cose_validate_context *
lws_cose_validate_create(const lws_cose_validate_create_info_t *info)
{
	struct lws_cose_validate_context *cps;

	/* you have to provide at least one key in a cose_keyset */
	assert(info->keyset);
	/* you have to provide an lws_context (for crypto random) */
	assert(info->cx);

	cps = lws_zalloc(sizeof(*cps), __func__);
	if (!cps)
		return NULL;

	cps->info			= *info;
	cps->tli			= ST_OUTER_PROTECTED;

	lecp_construct(&cps->ctx, cb_cose_sig, cps, NULL, 0);

	return cps;
}

int
lws_cose_validate_chunk(struct lws_cose_validate_context *cps,
			const uint8_t *in, size_t in_len, size_t *used_in)
{
	int n;

	n = lecp_parse(&cps->ctx, in, in_len);
	if (used_in)
		*used_in = cps->ctx.used_in;

	if (n == LECP_CONTINUE)
		return LECP_CONTINUE;

	lecp_destruct(&cps->ctx);

	return n;
}

lws_dll2_owner_t *
lws_cose_validate_results(struct lws_cose_validate_context *cps)
{
	return &cps->results;
}

void
lws_cose_validate_destroy(struct lws_cose_validate_context **_cps)
{
	struct lws_cose_validate_context *cps = *_cps;

	if (!cps)
		return;

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp,
				   lws_dll2_get_head(&cps->algs)) {
		lws_cose_sig_alg_t *alg = lws_container_of(p,
						lws_cose_sig_alg_t, list);

		lws_dll2_remove(p);
		lws_cose_val_alg_destroy(cps, &alg, NULL, 0);
	} lws_end_foreach_dll_safe(p, tp);

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp,
				   lws_dll2_get_head(&cps->results)) {
		lws_cose_validate_res_t *res = lws_container_of(p,
					lws_cose_validate_res_t, list);

		lws_dll2_remove(p);
		lws_free(res);
	} lws_end_foreach_dll_safe(p, tp);

	lws_free_set_NULL(cps->payload_stash);

	lwsac_free(&cps->ac);

	while (cps->sp >= 0) {
		if (cps->st[cps->sp].kid.buf)
			lws_free(cps->st[cps->sp].kid.buf);
		cps->sp--;
	}

	lws_free_set_NULL(*_cps);
}
