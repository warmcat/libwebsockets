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
#include <unistd.h>


#if defined(LWS_WITH_LS_QPACK)
#include <lsqpack.h>
#include <lsxpack_header.h>
#endif

#include <dirent.h>
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
	lws_qpack_dynamic_size(&qctx, 4096);
	
	states_len = 64;
	states = calloc(states_len, sizeof(*states));
	
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
	lseek(fd, 0, SEEK_SET);
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
		      
		s = read(fd, buf, len);
		if (s != (ssize_t)len) break;
		
		if (stream_id != 0) {
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
	
	close(fd);
	if (states)
		free(states);
	lws_qpack_destroy_dynamic_header(&qctx);
	return fails;
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
	
	/* 1. lws_qpack_get_static_token */
	if (lws_qpack_get_static_token(0, &tok, &val)) { lwsl_err("1.1\n"); fails++; }
	if (tok != WSI_TOKEN_HTTP_COLON_AUTHORITY || strcmp(val, "")) { lwsl_err("1.2\n"); fails++; }
	
	if (lws_qpack_get_static_token(17, &tok, &val)) { lwsl_err("1.3\n"); fails++; }
	if (tok != WSI_TOKEN_HTTP_COLON_METHOD || strcmp(val, "GET")) { lwsl_err("1.4\n"); fails++; }
	
	if (lws_qpack_get_static_token(98, &tok, &val)) { lwsl_err("1.5\n"); fails++; }
	if (tok != LWS_QPACK_IGNORE_ENTRY || strcmp(val, "sameorigin")) { lwsl_err("1.6\n"); fails++; }

	/* 2. lws_qpack_find_static_index */
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

	len = lws_qpack_encode_string(buf, sizeof(buf), "A very long string that exceeds the normal 7 bit prefix threshold of 127 bytes by being repeated. A very long string that exceeds the normal 7 bit prefix threshold of 127 bytes by being repeated.", 197);
	if (len != 199 || buf[0] != 0x7f || buf[1] != (197 - 127) || buf[2] != 'A') { lwsl_err("4.2\n"); fails++; }

	/* 5. Native Encoder Primitives */
	{
		unsigned char enc_buf[256];
		size_t p = 0;
		int n;
		
		n = lws_qpack_encode_prefix(enc_buf + p, sizeof(enc_buf) - p, 0, 0, 0);
		if (n != 2 || enc_buf[p] != 0x00 || enc_buf[p+1] != 0x00) { lwsl_err("5.1\n"); fails++; }
		p += (size_t)n;
		
		n = lws_qpack_encode_literal_with_name_ref(enc_buf + p, sizeof(enc_buf) - p, 15, "OTHER", 5);
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
		DIR *d = opendir("../minimal-examples-lowlevel/api-tests/api-test-qpack/qifs/encoded/qpack-06/ls-qpack");
		struct dirent *dir;
		lwsl_user("\n--- 7. QIF Interop Decoder Test (ALL datasets) ---\n");
		if (d) {
			while ((dir = readdir(d)) != NULL) {
				if (strstr(dir->d_name, ".out")) {
					char path[512];
					snprintf(path, sizeof(path), "../minimal-examples-lowlevel/api-tests/api-test-qpack/qifs/encoded/qpack-06/ls-qpack/%s", dir->d_name);
					fails += test_qif_file(path);
				}
			}
			closedir(d);
		}
	}
	
	/* 8. Run LWS Encoder Roundtrip against ALL QIF Plaintext Datasets */
	{
		DIR *d = opendir("../minimal-examples-lowlevel/api-tests/api-test-qpack/qifs/qifs");
		struct dirent *dir;
		lwsl_user("\n--- 8. QIF Interop Encoder Roundtrip Test (ALL datasets) ---\n");
		if (d) {
			while ((dir = readdir(d)) != NULL) {
				if (strstr(dir->d_name, ".qif")) {
					char path[512];
					snprintf(path, sizeof(path), "../minimal-examples-lowlevel/api-tests/api-test-qpack/qifs/qifs/%s", dir->d_name);
					/* lwsl_user("Roundtripping %s\n", path); */
					fails += test_qif_roundtrip(context, path);
				}
			}
			closedir(d);
		}
	}
	
	fails += test_qpack_encoder(context);

	if (fails) {
		lwsl_err("Failed %d tests\n", fails);
		lws_context_destroy(context);
		return 1;
	}

	lwsl_user("Completed: PASS\n");

	lws_context_destroy(context);

	return 0;
}
