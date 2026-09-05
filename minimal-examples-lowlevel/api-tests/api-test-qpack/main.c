/*
 * lws-api-test-qpack
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <fcntl.h>
#if defined(WIN32) || defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif


#if defined(LWS_WITH_LS_QPACK)
#include <lsqpack.h>
#include <lsxpack_header.h>
#endif


#include <sys/types.h>

void lws_free(void *p);

static int test_qpack_cb(void *user, int name_idx, const char *name, size_t name_len, const char *value, size_t value_len)
{
	/* lwsl_user("Decode CB: idx %d, name '%s', val '%s'\n", name_idx, name ? name : "", value ? value : ""); */
	return 0;
}

static int test_qpack_encoder(struct lws_context *ctx)
{
	unsigned char buf[2048];
	unsigned char *p = buf;
	unsigned char *end = buf + sizeof(buf);
	struct lws_qpack_stream_state state;
	struct lws_qpack_context qctx;
	int fails = 0;
	
	struct lws_qpack_tx_encoder tx_enc;
	struct lws_qpack_tx_table_entry tx_entries[16];
	struct lws *wsi;
	
	memset(&state, 0, sizeof(state));
	memset(&qctx, 0, sizeof(qctx));
	qctx.dyn_table.virtual_payload_limit = 4096;
	lws_qpack_dynamic_size(&qctx, 4096);
	memset(&tx_enc, 0, sizeof(tx_enc));
	tx_enc.entries = tx_entries;
	tx_enc.num_entries = 16;
	tx_enc.virtual_payload_max = 4096;

	wsi = lws_create_h3_dummy_wsi(ctx, &tx_enc);

	lwsl_user("\n--- 8. QPACK Encoder Test (Phase 4) ---\n");

	/* Encode a few headers:
	 * :status: 200
	 * server: libwebsockets
	 * my-custom-header: foo
	 */
	if (lws_add_http3_header_status(wsi, 200, &p, end)) { lwsl_err("enc status fail\n"); fails++; }
	if (lws_add_http3_header_by_token(wsi, WSI_TOKEN_HTTP_SERVER, (const unsigned char *)"libwebsockets", 13, &p, end)) { lwsl_err("enc server fail\n"); fails++; }
	if (lws_add_http3_header_by_name(wsi, (const unsigned char *)"my-custom-header:", (const unsigned char *)"foo", 3, &p, end)) { lwsl_err("enc custom fail\n"); fails++; }
	
	/* Second custom header with same string to trigger cache hit */
	if (lws_add_http3_header_by_name(wsi, (const unsigned char *)"my-custom-header:", (const unsigned char *)"foo", 3, &p, end)) { lwsl_err("enc custom fail\n"); fails++; }

	/* Finalize to write prefix */
	if (lws_finalize_http_header(wsi, &p, end)) { lwsl_err("finalize fail\n"); fails++; }

	/* Decode the generated encoder stream */
	{
		size_t len = lws_buflist_total_len(&tx_enc.tx_bl);
		if (len) {
			uint8_t enc_buf[1024];
			lws_buflist_linear_copy(&tx_enc.tx_bl, 0, enc_buf, len);
			lwsl_user("Encoded %d bytes of encoder stream.\n", (int)len);
			if (lws_qpack_decode_encoder_stream(&state, &qctx, enc_buf, len)) {
				lwsl_err("Failed to decode encoder stream\n");
				fails++;
			}
		}
	}

	/* Decode the generated block */
	lwsl_user("Encoded %d bytes of request stream.\n", (int)lws_ptr_diff(p, buf));
	if (lws_qpack_decode_header_block(&state, &qctx, buf, lws_ptr_diff_size_t(p, buf), test_qpack_cb, &fails)) {
		lwsl_err("Failed to decode encoder output\n");
		fails++;
	}

	lws_qpack_tx_encoder_destroy(&tx_enc);
	lws_qpack_destroy_dynamic_header(&qctx);
	lws_destroy_h3_dummy_wsi(wsi);
	return fails;
}

/*
 * F-015: a peer can stretch any varint on the QPACK encoder stream or a
 * header block with endless continuation bytes.  After 9 continuation
 * bytes int_shift is 63; from the 11th onwards the accumulation would
 * shift by >= 70 bits, which is undefined behavior in C rather than a
 * masked shift.  Both varint consumers must fail the decode cleanly
 * before that point, while still accepting well-formed extended varints.
 */
static int test_qpack_varint_limits(void)
{
	struct lws_qpack_stream_state state;
	struct lws_qpack_context qctx;
	int fails = 0;

	lwsl_user("\n--- 9. QPACK over-long varint rejection (F-015) ---\n");

	memset(&qctx, 0, sizeof(qctx));
	/* ops-h3.c sets this from LWS_QPACK_CAP_VAL before any decode */
	qctx.dyn_table.virtual_payload_limit = 4096;

	/* Well-formed 2-byte-extended Set Capacity (4096) must be accepted */
	{
		static const uint8_t cap[] = {
			0x3f,			/* 001|11111: Set Capacity, extended */
			0xe1, 0x1f,		/* 97 + 31 << 7 => capacity 4096 */
		};

		memset(&state, 0, sizeof(state));
		state.state = LQP_DEC_INSTRUCTION;
		if (lws_qpack_decode_encoder_stream(&state, &qctx,
						    cap, sizeof(cap))) {
			lwsl_err("9.1: legit extended Set Capacity rejected\n");
			fails++;
		}
	}

	/*
	 * Set Capacity whose varint never converges: the 11th continuation
	 * byte would accumulate at shift 70.  Must fail, not compute it.
	 */
	{
		static const uint8_t overlong[] = {
			0x3f,			/* 001|11111: Set Capacity, extended */
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff,	/* 10 bytes: int_shift reaches 63 */
			0xff,			/* ...this one would shift by 70 bits */
			0x01
		};

		memset(&state, 0, sizeof(state));
		state.state = LQP_DEC_INSTRUCTION;
		if (!lws_qpack_decode_encoder_stream(&state, &qctx,
						     overlong, sizeof(overlong))) {
			lwsl_err("9.2: over-long encoder stream varint accepted\n");
			fails++;
		}
	}

	/* Same property on the header block decoder, via Indexed Field Line */
	{
		static const uint8_t blk[] = {
			0x00, 0x00,		/* header block prefix: RIC=0, Base=0 */
			0xff,			/* 1|111111: Indexed Field Line, extended */
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0x01
		};

		memset(&state, 0, sizeof(state));
		if (!lws_qpack_decode_header_block(&state, NULL, blk,
						   sizeof(blk),
						   test_qpack_cb, &fails)) {
			lwsl_err("9.3: over-long header block varint accepted\n");
			fails++;
		}
	}

	/* Well-formed extended Indexed Field Line (static idx 65) is accepted */
	{
		static const uint8_t blk[] = {
			0x00, 0x00,		/* header block prefix: RIC=0, Base=0 */
			0xff, 0x02,		/* 1|111111 + 2 => static index 65 */
		};

		memset(&state, 0, sizeof(state));
		if (lws_qpack_decode_header_block(&state, NULL, blk,
						  sizeof(blk),
						  test_qpack_cb, &fails)) {
			lwsl_err("9.4: legit extended header block varint rejected\n");
			fails++;
		}
	}

	lws_qpack_destroy_dynamic_header(&qctx);

	return fails;
}

/*
 * A peer can Set Capacity such that the kept entries exactly fill the
 * shrunken table.  The next-write ring slot must wrap to 0 then, not point
 * one past the end of the entries array for the next insert to write
 * through, corrupting the heap.
 */
static int test_qpack_shrink_ring_bounds(void)
{
	struct lws_qpack_stream_state state;
	struct lws_qpack_context qctx;
	int fails = 0;

	lwsl_user("\n--- 10. QPACK shrink-to-full ring bounds ---\n");

	{
		static const uint8_t shrink_full[] = {
			0x3f, 0xe1, 0x1f,	/* Set Capacity 4096 => 128 slots */
			0xcf, 0x01, 'a',	/* Insert Name Ref static 15, "a" */
			0xcf, 0x01, 'b',	/* Insert Name Ref static 15, "b" */
			0x3f, 0x21,		/* Set Capacity 64 => 2 slots, full */
			0x00,			/* Duplicate dynamic index 0 */
		};

		memset(&state, 0, sizeof(state));
		state.state = LQP_DEC_INSTRUCTION;
		memset(&qctx, 0, sizeof(qctx));
		qctx.dyn_table.virtual_payload_limit = 4096;

		if (lws_qpack_decode_encoder_stream(&state, &qctx,
						    shrink_full,
						    sizeof(shrink_full))) {
			lwsl_err("10.1: legit shrink-to-full stream rejected\n");
			fails++;
		}
	}

	lws_qpack_destroy_dynamic_header(&qctx);

	return fails;
}

/*
 * 11. Browser-shaped dynamic table regression.
 *
 * Real-browser QPACK encoders (which use the dynamic table we invite with
 * SETTINGS_QPACK_MAX_TABLE_CAPACITY) insert entries on the encoder stream
 * -- including "Insert With Name Reference" to a dynamic entry when a
 * header NAME repeats with a different VALUE -- and reference them from
 * the field block.  Two regressions silently lost such headers, matching
 * the live "SSO POST arrives with no origin/referer" failure:
 *
 *   - the decoder-side dynamic table storage never existing, so every
 *     insert was refused and every reference skipped silently
 *   - a dynamic reference that resolves to nothing being dropped instead
 *     of failed
 *
 * This drives the exact wire shape Chrome produces for
 * origin: https://auth.warmcat.com after origin: https://warmcat.com was
 * already tabled by an earlier request on the same connection.
 */

struct browser_shape_state {
	int fails;
	int got_method_get;
	int got_origin_auth;
};

static int
test_browser_shape_cb(void *user, int name_idx, const char *name,
		      size_t name_len, const char *value, size_t value_len)
{
	struct browser_shape_state *b = (struct browser_shape_state *)user;

	if (!name && name_idx == WSI_TOKEN_HTTP_COLON_METHOD &&
	    value && value_len == 3 && !memcmp(value, "GET", 3))
		b->got_method_get = 1;

	if (name && name_len == 6 && !memcmp(name, "origin", 6) &&
	    value && value_len == 24 &&
	    !memcmp(value, "https://auth.warmcat.com", 24))
		b->got_origin_auth = 1;

	return 0;
}

static int test_qpack_browser_shape(void)
{
	struct lws_qpack_stream_state enc_state, hdr_state;
	static struct lws_qpack_dynamic_table_entry entries[128];
	struct lws_qpack_context qctx;
	struct browser_shape_state b;

	lwsl_user("\n--- 11. QPACK browser-shaped dynamic table ---\n");

	memset(&b, 0, sizeof(b));
	memset(&qctx, 0, sizeof(qctx));

	/* exactly what ops-h3 wires up for an h3 connection's decoder */
	qctx.dyn_table.entries = entries;
	qctx.dyn_table.num_entries = LWS_ARRAY_SIZE(entries);
	qctx.dyn_table.virtual_payload_limit = 4096;

	{
		/* Set Dynamic Table Capacity 4096 */
		static const uint8_t setcap[] = { 0x3f, 0xe1, 0x1f };
		/* Insert literal name "origin", value "https://warmcat.com" (19) */
		static const uint8_t ins1[] = {
			0x46, 'o','r','i','g','i','n',
			19, 'h','t','t','p','s',':','/','/','w','a','r','m','c','a','t','.','c','o','m'
		};
		/* Insert With Name Reference (dynamic rel 0), value
		 * "https://auth.warmcat.com" (24) */
		static const uint8_t ins2[] = {
			0x80, 24,
			'h','t','t','p','s',':','/','/','a','u','t','h','.','w','a','r','m','c','a','t','.','c','o','m'
		};
		/* Field block: wire Ric = (2 mod 256) + 1 = 3, S=0 delta 0
		 * => base = 2; :method GET (static 18); indexed dynamic
		 * relative 0 = the auth origin insert */
		static const uint8_t block[] = { 0x03, 0x00, 0xd1, 0x80 };

		memset(&enc_state, 0, sizeof(enc_state));
		enc_state.state = LQP_DEC_INSTRUCTION;

		if (lws_qpack_decode_encoder_stream(&enc_state, &qctx, setcap,
						    sizeof(setcap)) ||
		    lws_qpack_decode_encoder_stream(&enc_state, &qctx, ins1,
						    sizeof(ins1)) ||
		    lws_qpack_decode_encoder_stream(&enc_state, &qctx, ins2,
						    sizeof(ins2))) {
			lwsl_err("11.1: encoder stream rejected\n");
			b.fails++;
		}

		if (qctx.dyn_table.used_entries != 2 ||
		    qctx.dyn_table.insert_count != 2) {
			lwsl_err("11.2: inserts not retained (used %u, count %u)\n",
				 qctx.dyn_table.used_entries,
				 qctx.dyn_table.insert_count);
			b.fails++;
		}

		memset(&hdr_state, 0, sizeof(hdr_state));
		if (lws_qpack_decode_header_block(&hdr_state, &qctx, block,
						  sizeof(block),
						  test_browser_shape_cb, &b)) {
			lwsl_err("11.3: field block rejected\n");
			b.fails++;
		}

		if (!b.got_method_get) {
			lwsl_err("11.4: static :method GET lost\n");
			b.fails++;
		}

		if (!b.got_origin_auth) {
			lwsl_err("11.5: dynamic origin reference LOST\n");
			b.fails++;
		}

		/*
		 * 11.6: a capacity change on a table with embedded storage
		 * must adjust the byte budget and evict, never free or resize
		 * the caller's entries array.  96 bytes has a different slot
		 * count than 4096, which is exactly the case that used to
		 * free the embedded array and corrupt the heap
		 */
		{
			static const uint8_t shrink96[] = { 0x3f, 0x41 };
			/* 8192 with a 4096 limit must be rejected loudly */
			static const uint8_t overlimit[] = { 0x3f, 0xe1, 0x3f };

			if (lws_qpack_decode_encoder_stream(&enc_state, &qctx,
							    shrink96,
							    sizeof(shrink96))) {
				lwsl_err("11.6: legit capacity shrink rejected\n");
				b.fails++;
			}

			if (qctx.dyn_table.entries != entries) {
				lwsl_err("11.7: embedded entries array replaced\n");
				b.fails++;
			}

			if (!lws_qpack_decode_encoder_stream(&enc_state, &qctx,
							     overlimit,
							     sizeof(overlimit))) {
				lwsl_err("11.8: over-limit capacity accepted\n");
				b.fails++;
			}
		}
	}

	lws_qpack_destroy_dynamic_header(&qctx);

	return b.fails;
}

struct test_qif_state {
	int fails;
	int expected_idx;
	char *names[1024];
	char *values[1024];
	int num_headers;
};

static int
test_qif_roundtrip_cb(void *user, int name_idx, const char *name, size_t name_len, const char *value, size_t value_len)
{
	struct test_qif_state *s = (struct test_qif_state *)user;
	
	if (s->expected_idx >= s->num_headers) {
		lwsl_err("Too many headers decoded!\n");
		s->fails++;
		return 1;
	}
	
	const char *exp_name = s->names[s->expected_idx];
	const char *exp_val = s->values[s->expected_idx];
	
	const char *v1 = value ? value : "";
	const char *v2 = exp_val ? exp_val : "";
	const char *n1 = name ? name : "";
	const char *n2 = exp_name ? exp_name : "";
	
	if (!name && name_idx >= 0) {
		const unsigned char *name_str = lws_token_to_string((enum lws_token_indexes)name_idx);
		char clean_name[128] = "";
		if (name_str) {
			size_t len = strlen((const char *)name_str);
			if (len > 0 && name_str[len - 1] == ':') len--;
			strncpy(clean_name, (const char *)name_str, len);
			clean_name[len] = '\0';
		}
		
		if (!name_str || strcmp(clean_name, n2)) {
			lwsl_err("Name mismatch! expected %s, got static idx %d (%s)\n", n2, name_idx, clean_name);
			s->fails++;
		}
	} else if (name) {
		if (strncmp(n1, n2, name_len) || strlen(n2) != name_len) {
			lwsl_err("Name mismatch! expected '%s', got '%.*s' (len=%d)\n", n2, (int)name_len, n1, (int)name_len);
			s->fails++;
		}
	} else {
		lwsl_err("No name!\n");
		s->fails++;
	}
	
	if (strncmp(v1, v2, value_len) || strlen(v2) != value_len) {
		lwsl_err("Value mismatch! expected '%s', got '%.*s' (len=%d)\n", v2, (int)value_len, v1, (int)value_len);
		s->fails++;
	}
	
	s->expected_idx++;
	return 0;
}

static int
test_qif_roundtrip(struct lws_context *ctx, const char *filepath)
{
	int fails = 0, i;
	FILE *f = fopen(filepath, "r");
	char line[4096];
	unsigned char buf[65536];
	unsigned char *p = buf;
	unsigned char *end = buf + sizeof(buf);
	unsigned char *prefix_ptr = NULL;
	
	struct lws_qpack_stream_state state;
	struct lws_qpack_stream_state enc_state;
	struct lws_qpack_context qctx;
	struct lws_qpack_tx_encoder tx_enc;
	struct lws_qpack_tx_table_entry tx_entries[256];
	struct lws *wsi;
	struct test_qif_state s_state;
	uint32_t start_ric = 0;
	
	if (!f) {
		lwsl_err("Failed to open %s\n", filepath);
		return 1;
	}

	memset(&state, 0, sizeof(state));
	memset(&enc_state, 0, sizeof(enc_state));
	enc_state.state = LQP_DEC_INSTRUCTION;
	memset(&qctx, 0, sizeof(qctx));
	qctx.dyn_table.virtual_payload_limit = 4096;
	lws_qpack_dynamic_size(&qctx, 4096);
	memset(&tx_enc, 0, sizeof(tx_enc));
	tx_enc.entries = tx_entries;
	tx_enc.num_entries = 256;
	tx_enc.virtual_payload_max = 4096;
	
	wsi = lws_create_h3_dummy_wsi(ctx, &tx_enc);
	s_state.fails = 0;
	s_state.num_headers = 0;
	
	while (fgets(line, sizeof(line), f)) {
		if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
			/* Empty line indicates end of a stream block! */
			if (s_state.num_headers > 0) {
				/* Write prefix manually using the block's RIC */
				if (prefix_ptr) {
					uint32_t ric = tx_enc.insert_count;
					uint32_t max_entries = tx_enc.virtual_payload_max / 32;
					uint8_t pre[16];
					int pre_len = lws_qpack_encode_prefix(pre, 16, ric, start_ric, max_entries);
					if (pre_len > 0 && pre_len <= 16) {
						memcpy(buf + 16 - pre_len, pre, (size_t)pre_len);
						prefix_ptr = buf + 16 - pre_len;
					}
				}
				
				/* Decode encoder stream */
				{
					size_t len = lws_buflist_total_len(&tx_enc.tx_bl);
					if (len > 0) {
						uint8_t enc_buf[1024];
						if (len > sizeof(enc_buf)) len = sizeof(enc_buf);
						lws_buflist_linear_copy(&tx_enc.tx_bl, 0, enc_buf, len);
						if (lws_qpack_decode_encoder_stream(&enc_state, &qctx, enc_buf, len)) {
							lwsl_err("Encoder stream decode failed in %s\n", filepath);
							fails++;
						}
						lws_buflist_destroy_all_segments(&tx_enc.tx_bl);
					}
				}
				
				/* Decode header block */
				s_state.expected_idx = 0;
				if (prefix_ptr) {
					memset(&state, 0, sizeof(state)); /* Reset block state */
					if (lws_qpack_decode_header_block(&state, &qctx, prefix_ptr, lws_ptr_diff_size_t(p, prefix_ptr), test_qif_roundtrip_cb, &s_state)) {
						lwsl_err("Header block decode failed in %s\n", filepath);
						fails++;
					}
				}
				if (s_state.expected_idx != s_state.num_headers) {
					lwsl_err("Missing headers! expected %d got %d\n", s_state.num_headers, s_state.expected_idx);
					fails++;
				}
				fails += s_state.fails;
				
				/* Reset block state */
				for (i = 0; i < s_state.num_headers; i++) {
					free(s_state.names[i]);
					free(s_state.values[i]);
				}
				s_state.num_headers = 0;
				s_state.fails = 0;
				p = buf + 16; /* reset buffer */
				prefix_ptr = NULL;
			}
			continue;
		}
		
		/* Parse name\tvalue */
		char *tab = strchr(line, '\t');
		if (!tab) continue;
		*tab = '\0';
		char *val = tab + 1;
		char *nl = strchr(val, '\n');
		if (nl) *nl = '\0';
		nl = strchr(val, '\r');
		if (nl) *nl = '\0';
		
		s_state.names[s_state.num_headers] = strdup(line);
		s_state.values[s_state.num_headers] = strdup(val);
		s_state.num_headers++;
		
		/* Encode it! */
		if (!prefix_ptr) {
			/* We must reserve prefix for the new block */
			prefix_ptr = buf + 14; /* Dummy to indicate it's active */
			p = buf + 16;
			start_ric = tx_enc.insert_count;
			lws_qpack_set_wsi_base_and_ric(wsi, start_ric, start_ric);
		}
		
		/* Needs a colon at the end of the name for lws_add_http3_header_by_name */
		char name_colon[4098];
		snprintf(name_colon, sizeof(name_colon), "%s:", line);
		lws_add_http3_header_by_name(wsi, (unsigned char *)name_colon, (unsigned char *)val, (int)strlen(val), &p, end);
	}
	
	for (i = 0; i < s_state.num_headers; i++) {
		free(s_state.names[i]);
		free(s_state.values[i]);
	}
	s_state.num_headers = 0;
	
	fclose(f);
	lws_qpack_destroy_dynamic_header(&qctx);
	lws_qpack_tx_encoder_destroy(&tx_enc);
	lws_destroy_h3_dummy_wsi(wsi);
	return fails;
}

static int
test_qif_file(const char *filepath)
{
	int fd, fails = 0;
	ssize_t s;
	unsigned char header[12];
	uint64_t stream_id;
	uint32_t len;
	unsigned char buf[65536];
	struct lws_qpack_stream_state *states = NULL;
	uint64_t states_len = 0;
	struct lws_qpack_context qctx;
	
	fd = open(filepath, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Failed to open %s\n", filepath);
		return 1;
	}

	memset(&qctx, 0, sizeof(qctx));
	qctx.dyn_table.virtual_payload_limit = 4096;
	lws_qpack_dynamic_size(&qctx, 4096);
	
	states_len = 64;
	states = calloc(states_len, sizeof(*states));
	if (!states) {
		lwsl_err("OOM\n");
		fails++;
		goto done;
	}
	
	/* Encoder stream starts directly with instructions, no prefix */
	states[0].state = LQP_DEC_INSTRUCTION;

	/* Pass 1: Encoder stream */
	while (1) {
		s = read(fd, header, 12);
		if (s == 0) break;
		if (s != 12) {
			lwsl_err("Truncated header\n");
			fails++;
			break;
		}
		
		stream_id = ((uint64_t)header[0] << 56) | ((uint64_t)header[1] << 48) |
			      ((uint64_t)header[2] << 40) | ((uint64_t)header[3] << 32) |
			      ((uint64_t)header[4] << 24) | ((uint64_t)header[5] << 16) |
			      ((uint64_t)header[6] << 8) | header[7];
			      
		len = ((uint32_t)header[8] << 24) | ((uint32_t)header[9] << 16) |
		      ((uint32_t)header[10] << 8) | header[11];
		      
		if (len > sizeof(buf)) {
			lwsl_err("Too big block %u\n", (unsigned int)len);
			fails++;
			break;
		}
		
		s = read(fd, buf, len);
		if (s != (ssize_t)len) {
			lwsl_err("Truncated data\n");
			fails++;
			break;
		}
		
		if (stream_id == 0) {
			if (lws_qpack_decode_encoder_stream(&states[0], &qctx, buf, len)) {
				lwsl_err("Encoder stream decode failed\n");
				fails++;
			}
		}
	}
	
	/* Pass 2: Header blocks */
	if (lseek(fd, 0, SEEK_SET) < 0) {
		lwsl_err("lseek failed\n");
		fails++;
		goto done;
	}
	while (1) {
		s = read(fd, header, 12);
		if (s == 0) break;
		if (s != 12) break;
		
		stream_id = ((uint64_t)header[0] << 56) | ((uint64_t)header[1] << 48) |
			      ((uint64_t)header[2] << 40) | ((uint64_t)header[3] << 32) |
			      ((uint64_t)header[4] << 24) | ((uint64_t)header[5] << 16) |
			      ((uint64_t)header[6] << 8) | header[7];
			      
		len = ((uint32_t)header[8] << 24) | ((uint32_t)header[9] << 16) |
		      ((uint32_t)header[10] << 8) | header[11];
		      
		if (len > sizeof(buf)) {
			lwsl_err("Too big block %u\n", (unsigned int)len);
			fails++;
			break;
		}

		s = read(fd, buf, len);
		if (s != (ssize_t)len) break;
		
		if (stream_id != 0) {
			if (stream_id > 100000) {
				lwsl_err("stream_id %llu too large\n", (unsigned long long)stream_id);
				fails++;
				break;
			}
			if (stream_id >= states_len) {
				uint64_t new_len = stream_id + 64;
				struct lws_qpack_stream_state *ns = realloc(states, (size_t)(new_len * sizeof(*states)));
				if (!ns) {
					lwsl_err("OOM\n");
					fails++;
					break;
				}
				memset(ns + states_len, 0, (size_t)((new_len - states_len) * sizeof(*states)));
				states = ns;
				states_len = new_len;
			}
			
			if (lws_qpack_decode_header_block(&states[stream_id], &qctx, buf, len, test_qpack_cb, &fails)) {
				lwsl_err("Header block decode failed on stream %llu\n", (unsigned long long)stream_id);
				fails++;
			}
		}
	}
	
done:
	close(fd);
	if (states)
		free(states);
	lws_qpack_destroy_dynamic_header(&qctx);
	return fails;
}

struct qif_test_ctx {
	struct lws_context *cx;
	int fails;
	int is_roundtrip;
};

static int
qif_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct qif_test_ctx *qctx = (struct qif_test_ctx *)user;
	char path[512];

	if (lde->type != LDOT_FILE)
		return 0;

	if (qctx->is_roundtrip) {
		if (strstr(lde->name, ".qif")) {
			snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
			qctx->fails += test_qif_roundtrip(qctx->cx, path);
		}
	} else {
		if (strstr(lde->name, ".out")) {
			snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
			qctx->fails += test_qif_file(path);
		}
	}

	return 0;
}

int main(int argc, const char **argv)
{
	
	struct lws_context_creation_info info;
	struct lws_context *context;
	int tok, fails = 0;
	const char *val;
	unsigned char buf[256];
	int len;

	lwsl_user("LWS QPACK API tests\n");

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

#if defined(LWS_WITH_LS_QPACK)
	lwsl_user("Compiled with ls-qpack testing support (Version: %u.%u.%u)\n",
		  LSQPACK_MAJOR_VERSION, LSQPACK_MINOR_VERSION, LSQPACK_PATCH_VERSION);
#endif

	/* 
	 * Phase 1 Testing: Static Table & Encoded Integer Sanity Checks
	 */
	
	/*
	 * 1. lws_qpack_get_static_token: RFC 9204's static table is 0-based
	 * on the wire (index 0 is :authority), unlike HPACK
	 */
	if (lws_qpack_get_static_token(0, &tok, &val)) { lwsl_err("1.1\n"); fails++; }
	if (tok != WSI_TOKEN_HTTP_COLON_AUTHORITY || strcmp(val, "")) { lwsl_err("1.2\n"); fails++; }

	if (lws_qpack_get_static_token(17, &tok, &val)) { lwsl_err("1.3\n"); fails++; }
	if (tok != WSI_TOKEN_HTTP_COLON_METHOD || strcmp(val, "GET")) { lwsl_err("1.4\n"); fails++; }

	if (lws_qpack_get_static_token(98, &tok, &val)) { lwsl_err("1.5\n"); fails++; }
	if (tok != LWS_QPACK_IGNORE_ENTRY || strcmp(val, "sameorigin")) { lwsl_err("1.6\n"); fails++; }

	if (!lws_qpack_get_static_token(99, &tok, &val)) { lwsl_err("1.7\n"); fails++; }

	/* 2. lws_qpack_find_static_index returns the 0-based wire index */
	if (lws_qpack_find_static_index(WSI_TOKEN_HTTP_COLON_METHOD, "GET", 3) != 17) { lwsl_err("2.1\n"); fails++; }
	if (lws_qpack_find_static_index(WSI_TOKEN_HTTP_COLON_METHOD, "POST", 4) != 20) { lwsl_err("2.2\n"); fails++; }
	if (lws_qpack_find_static_index(WSI_TOKEN_HTTP_COLON_STATUS, "200", 3) != 25) { lwsl_err("2.3\n"); fails++; }

	/* 3. lws_qpack_encode_static */
	len = lws_qpack_encode_static(buf, sizeof(buf), 0);
	if (len != 1 || buf[0] != 0xc0) { lwsl_err("3.1\n"); fails++; }

	len = lws_qpack_encode_static(buf, sizeof(buf), 62);
	if (len != 1 || buf[0] != 0xfe) { lwsl_err("3.2\n"); fails++; }
	
	len = lws_qpack_encode_static(buf, sizeof(buf), 63);
	if (len != 2 || buf[0] != 0xff || buf[1] != 0x00) { lwsl_err("3.3\n"); fails++; }
	
	len = lws_qpack_encode_static(buf, sizeof(buf), 64);
	if (len != 2 || buf[0] != 0xff || buf[1] != 0x01) { lwsl_err("3.4\n"); fails++; }

	len = lws_qpack_encode_static(buf, sizeof(buf), 98);
	if (len != 2 || buf[0] != 0xff || buf[1] != 35) { lwsl_err("3.5\n"); fails++; }

	/* 4. lws_qpack_encode_string */
	len = lws_qpack_encode_string(buf, sizeof(buf), "hello", 5);
	if (len != 6 || buf[0] != 0x05 || memcmp(buf + 1, "hello", 5)) { lwsl_err("4.1\n"); fails++; }

	/* 4.2: string longer than the 7-bit prefix threshold, extended len */

	{
		static const char longstr[] = "A very long string that exceeds the "
			"normal 7 bit prefix threshold of 127 bytes by being "
			"repeated. A very long string that exceeds the normal "
			"7 bit prefix threshold of 127 bytes by being repeated.";
		size_t longlen = strlen(longstr);

		len = lws_qpack_encode_string(buf, sizeof(buf), longstr, longlen);
		if (len != (int)(2 + longlen) || buf[0] != 0x7f ||
		    buf[1] != (int)(longlen - 127) || buf[2] != 'A') { lwsl_err("4.2\n"); fails++; }
	}

	/* 5. Native Encoder Primitives */
	{
		unsigned char enc_buf[256];
		size_t p = 0;
		int n;
		
		n = lws_qpack_encode_prefix(enc_buf + p, sizeof(enc_buf) - p, 0, 0, 0);
		if (n != 2 || enc_buf[p] != 0x00 || enc_buf[p+1] != 0x00) { lwsl_err("5.1\n"); fails++; }
		p += (size_t)n;
		
		n = lws_qpack_encode_literal_with_name_ref(enc_buf + p, sizeof(enc_buf) - p, 15, "OTHER", 5); /* static name idx 15 = set-cookie */
		if (n != 8 || enc_buf[p] != 0x5f || enc_buf[p+1] != 0x00 || enc_buf[p+2] != 0x05) { lwsl_err("5.2\n"); fails++; }
		p += (size_t)n;
		
		n = lws_qpack_encode_literal_with_literal_name(enc_buf + p, sizeof(enc_buf) - p, "foo", 3, "bar", 3);
		if (n != 8 || enc_buf[p] != 0x23 || enc_buf[p+1] != 'f' || enc_buf[p+4] != 0x03) { lwsl_err("5.3\n"); fails++; }
		p += (size_t)n;
		
		/* Decode them back natively */
		{
			struct lws_qpack_stream_state state;
			memset(&state, 0, sizeof(state));
			lws_qpack_decode_header_block(&state, NULL, enc_buf, (size_t)p, test_qpack_cb, &fails);
		}
	}

	/* 6. Decoder State Machine Test */
	{
		struct lws_qpack_stream_state state;
		unsigned char test_block[] = {
			0x00, 0x00, /* Prefix: RIC=0, Base=0 */
			0xd1,       /* Indexed Field Line: static index 17 (:method GET) */
			0x5f, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o', /* Literal with Name Ref: static index 15 (:method), value "hello" */
			0x23, 'f', 'o', 'o', 0x03, 'b', 'a', 'r' /* Literal with Literal Name: N=0, H=0, len=3 "foo", len=3 "bar" */
		};
		memset(&state, 0, sizeof(state));
		lws_qpack_decode_header_block(&state, NULL, test_block, sizeof(test_block), test_qpack_cb, &fails);
	}

#if defined(LWS_WITH_LS_QPACK)
	/* 6. ls-qpack Differential Round-Trip Test */
	{
		struct lsqpack_enc enc;
		struct lsxpack_header hdr[3];
		unsigned char enc_buf[256];
		unsigned char header_buf[256];
		size_t enc_sz = sizeof(enc_buf);
		size_t header_sz = sizeof(header_buf);
		struct lws_qpack_stream_state state;
		
		lwsl_user("Starting ls-qpack differential test...\n");
		
		/* 6.1 Initialize ls-qpack encoder (0 max dynamic table) */
		lsqpack_enc_preinit(&enc, NULL);
		lsqpack_enc_init(&enc, NULL, 0, 0, 0, LSQPACK_ENC_OPT_STAGE_2, NULL, NULL);
		
		/* 6.2 Prepare headers */
		lsxpack_header_set_qpack_idx(&hdr[0], LSQPACK_TNV_METHOD_GET, "GET", 3); /* :method GET */
		lsxpack_header_set_qpack_idx(&hdr[1], LSQPACK_TNV_METHOD_GET, "OTHER", 5); /* :method OTHER */
		lsxpack_header_set_offset2(&hdr[2], "foo\0bar", 0, 3, 4, 3); /* foo: bar */

		/* 6.3 Encode using ls-qpack */
		lsqpack_enc_start_header(&enc, 1, 0);
		lsqpack_enc_encode(&enc, enc_buf, &enc_sz, header_buf, &header_sz, &hdr[0], 0);
		
		/* Note: We append to header_buf by adjusting the pointers */
		{
			size_t e_sz2 = sizeof(enc_buf) - enc_sz;
			size_t h_sz2 = sizeof(header_buf) - header_sz;
			lsqpack_enc_encode(&enc, enc_buf + enc_sz, &e_sz2, header_buf + header_sz, &h_sz2, &hdr[1], 0);
			enc_sz += e_sz2; header_sz += h_sz2;
			
			e_sz2 = sizeof(enc_buf) - enc_sz;
			h_sz2 = sizeof(header_buf) - header_sz;
			lsqpack_enc_encode(&enc, enc_buf + enc_sz, &e_sz2, header_buf + header_sz, &h_sz2, &hdr[2], 0);
			enc_sz += e_sz2; header_sz += h_sz2;
		}
		
		{
			unsigned char prefix_buf[32];
			ssize_t prefix_sz;
			unsigned char combined[512];
			
			prefix_sz = lsqpack_enc_end_header(&enc, prefix_buf, sizeof(prefix_buf), NULL);
			if (prefix_sz < 0) { lwsl_err("lsqpack_enc_end_header failed\n"); fails++; }
			
			memcpy(combined, prefix_buf, (size_t)prefix_sz);
			memcpy(combined + prefix_sz, header_buf, header_sz);
			header_sz += (size_t)prefix_sz;
			
			lwsl_user("ls-qpack emitted %d header block bytes.\n", (int)header_sz);
			lwsl_hexdump_user(combined, header_sz);
			
			/* 6.4 Decode using native LWS QPACK */
			memset(&state, 0, sizeof(state));
			lws_qpack_decode_header_block(&state, NULL, combined, header_sz, test_qpack_cb, &fails);
		}
		
		lsqpack_enc_cleanup(&enc);
	}
#endif

	/* 7. Run against ALL QIF Interop Outputs */
	{
		struct qif_test_ctx qctx = { context, 0, 0 };
		lwsl_user("\n--- 7. QIF Interop Decoder Test (ALL datasets) ---\n");
		lws_dir("../minimal-examples-lowlevel/api-tests/api-test-qpack/qifs/encoded/qpack-06/ls-qpack", &qctx, qif_dir_cb);
		fails += qctx.fails;
	}
	
	/* 8. Run LWS Encoder Roundtrip against ALL QIF Plaintext Datasets */
	{
		struct qif_test_ctx qctx = { context, 0, 1 };
		lwsl_user("\n--- 8. QIF Interop Encoder Roundtrip Test (ALL datasets) ---\n");
		lws_dir("../minimal-examples-lowlevel/api-tests/api-test-qpack/qifs/qifs", &qctx, qif_dir_cb);
		fails += qctx.fails;
	}
	
	fails += test_qpack_encoder(context);
	fails += test_qpack_varint_limits();
	fails += test_qpack_shrink_ring_bounds();
	fails += test_qpack_browser_shape();

	if (fails) {
		lwsl_err("Failed %d tests\n", fails);
		lws_context_destroy(context);
		return 1;
	}

	lwsl_user("Completed: PASS\n");

	lws_context_destroy(context);

	return 0;
}
