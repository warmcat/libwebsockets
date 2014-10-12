/*
 * lib/hpack.c
 *
 * Copyright (C) 2014 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "private-libwebsockets.h"

/*
 * Official static header table for HPACK
 *        +-------+-----------------------------+---------------+
          | 1     | :authority                  |               |
          | 2     | :method                     | GET           |
          | 3     | :method                     | POST          |
          | 4     | :path                       | /             |
          | 5     | :path                       | /index.html   |
          | 6     | :scheme                     | http          |
          | 7     | :scheme                     | https         |
          | 8     | :status                     | 200           |
          | 9     | :status                     | 204           |
          | 10    | :status                     | 206           |
          | 11    | :status                     | 304           |
          | 12    | :status                     | 400           |
          | 13    | :status                     | 404           |
          | 14    | :status                     | 500           |
          | 15    | accept-charset              |               |
          | 16    | accept-encoding             | gzip, deflate |
          | 17    | accept-language             |               |
          | 18    | accept-ranges               |               |
          | 19    | accept                      |               |
          | 20    | access-control-allow-origin |               |
          | 21    | age                         |               |
          | 22    | allow                       |               |
          | 23    | authorization               |               |
          | 24    | cache-control               |               |
          | 25    | content-disposition         |               |
          | 26    | content-encoding            |               |
          | 27    | content-language            |               |
          | 28    | content-length              |               |
          | 29    | content-location            |               |
          | 30    | content-range               |               |
          | 31    | content-type                |               |
          | 32    | cookie                      |               |
          | 33    | date                        |               |
          | 34    | etag                        |               |
          | 35    | expect                      |               |
          | 36    | expires                     |               |
          | 37    | from                        |               |
          | 38    | host                        |               |
          | 39    | if-match                    |               |
          | 40    | if-modified-since           |               |
          | 41    | if-none-match               |               |
          | 42    | if-range                    |               |
          | 43    | if-unmodified-since         |               |
          | 44    | last-modified               |               |
          | 45    | link                        |               |
          | 46    | location                    |               |
          | 47    | max-forwards                |               |
          | 48    | proxy-authenticate          |               |
          | 49    | proxy-authorization         |               |
          | 50    | range                       |               |
          | 51    | referer                     |               |
          | 52    | refresh                     |               |
          | 53    | retry-after                 |               |
          | 54    | server                      |               |
          | 55    | set-cookie                  |               |
          | 56    | strict-transport-security   |               |
          | 57    | transfer-encoding           |               |
          | 58    | user-agent                  |               |
          | 59    | vary                        |               |
          | 60    | via                         |               |
          | 61    | www-authenticate            |               |
          +-------+-----------------------------+---------------+
*/

static const unsigned char static_token[] = {
	0,
	WSI_TOKEN_HTTP_COLON_AUTHORITY,
	WSI_TOKEN_HTTP_COLON_METHOD,
	WSI_TOKEN_HTTP_COLON_METHOD,
	WSI_TOKEN_HTTP_COLON_PATH,
	WSI_TOKEN_HTTP_COLON_PATH,
	WSI_TOKEN_HTTP_COLON_SCHEME,
	WSI_TOKEN_HTTP_COLON_SCHEME,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_ACCEPT_CHARSET,
	WSI_TOKEN_HTTP_ACCEPT_ENCODING,
	WSI_TOKEN_HTTP_ACCEPT_LANGUAGE,
	WSI_TOKEN_HTTP_ACCEPT_RANGES,
	WSI_TOKEN_HTTP_ACCEPT,
	WSI_TOKEN_HTTP_ACCESS_CONTROL_ALLOW_ORIGIN,
	WSI_TOKEN_HTTP_AGE,
	WSI_TOKEN_HTTP_ALLOW,
	WSI_TOKEN_HTTP_AUTHORIZATION,
	WSI_TOKEN_HTTP_CACHE_CONTROL,
	WSI_TOKEN_HTTP_CONTENT_DISPOSITION,
	WSI_TOKEN_HTTP_CONTENT_ENCODING,
	WSI_TOKEN_HTTP_CONTENT_LANGUAGE,
	WSI_TOKEN_HTTP_CONTENT_LENGTH,
	WSI_TOKEN_HTTP_CONTENT_LOCATION,
	WSI_TOKEN_HTTP_CONTENT_RANGE,
	WSI_TOKEN_HTTP_CONTENT_TYPE,
	WSI_TOKEN_HTTP_COOKIE,
	WSI_TOKEN_HTTP_DATE,
	WSI_TOKEN_HTTP_ETAG,
	WSI_TOKEN_HTTP_EXPECT,
	WSI_TOKEN_HTTP_EXPIRES,
	WSI_TOKEN_HTTP_FROM,
	WSI_TOKEN_HOST,
	WSI_TOKEN_HTTP_IF_MATCH,
	WSI_TOKEN_HTTP_IF_MODIFIED_SINCE,
	WSI_TOKEN_HTTP_IF_NONE_MATCH,
	WSI_TOKEN_HTTP_IF_RANGE,
	WSI_TOKEN_HTTP_IF_UNMODIFIED_SINCE,
	WSI_TOKEN_HTTP_LAST_MODIFIED,
	WSI_TOKEN_HTTP_LINK,
	WSI_TOKEN_HTTP_LOCATION,
	WSI_TOKEN_HTTP_MAX_FORWARDS,
	WSI_TOKEN_HTTP_PROXY_AUTHENTICATE,
	WSI_TOKEN_HTTP_PROXY_AUTHORIZATION,
	WSI_TOKEN_HTTP_RANGE,
	WSI_TOKEN_HTTP_REFERER,
	WSI_TOKEN_HTTP_REFRESH,
	WSI_TOKEN_HTTP_RETRY_AFTER,
	WSI_TOKEN_HTTP_SERVER,
	WSI_TOKEN_HTTP_SET_COOKIE,
	WSI_TOKEN_HTTP_STRICT_TRANSPORT_SECURITY,
	WSI_TOKEN_HTTP_TRANSFER_ENCODING,
	WSI_TOKEN_HTTP_USER_AGENT,
	WSI_TOKEN_HTTP_VARY,
	WSI_TOKEN_HTTP_VIA,
	WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
};

/* some of the entries imply values as well as header names */

static const char * const http2_canned[] = {
	"",
	"",
	"GET",
	"POST",
	"/",
	"/index.html",
	"http",
	"https",
	"200",
	"204",
	"206",
	"304",
	"400",
	"404",
	"500",
	"",
	"gzip, deflate"
};

/* see minihuf.c */

#include "huftable.h"

static int huftable_decode(int pos, char c)
{
	int q = pos + !!c;

	if (lextable_terms[q >> 3] & (1 << (q & 7))) /* terminal */
		return lextable[q] | 0x8000;

	return pos + (lextable[q] << 1);
}

static int lws_hpack_update_table_size(struct libwebsocket *wsi, int idx)
{
	lwsl_info("hpack set table size %d\n", idx);
	return 0;
}

static int lws_frag_start(struct libwebsocket *wsi, int hdr_token_idx)
{
	struct allocated_headers * ah = wsi->u.http2.http.ah;

	if (!hdr_token_idx)
		return 1;
	
	if (ah->next_frag_index >= ARRAY_SIZE(ah->frag_index))
		return 1;
	
	ah->frags[ah->next_frag_index].offset = ah->pos;
	ah->frags[ah->next_frag_index].len = 0;
	ah->frags[ah->next_frag_index].next_frag_index = 0;

	ah->frag_index[hdr_token_idx] = ah->next_frag_index;
	
	return 0;
}

static int lws_frag_append(struct libwebsocket *wsi, unsigned char c)
{
	struct allocated_headers * ah = wsi->u.http2.http.ah;

	ah->data[ah->pos++] = c;
	ah->frags[ah->next_frag_index].len++;
	
	return ah->pos >= sizeof(ah->data);
}

static int lws_frag_end(struct libwebsocket *wsi)
{
	if (lws_frag_append(wsi, 0))
		return 1;

	wsi->u.http2.http.ah->next_frag_index++;
	return 0;
}

static void lws_dump_header(struct libwebsocket *wsi, int hdr)
{
	char s[200];
	int len = lws_hdr_copy(wsi, s, sizeof(s) - 1, hdr);
	s[len] = '\0';
	lwsl_info("  hdr tok %d '%s'\n", hdr, s);
}

static int lws_token_from_index(struct libwebsocket *wsi, int index)
{
	if (index < ARRAY_SIZE(static_token))
		return static_token[index];
	
	// dynamic indexes
	
	return 0;
}

static int lws_add_indexed_hdr(struct libwebsocket *wsi, int idx)
{
	const char *p;
	int tok = lws_token_from_index(wsi, idx);

	lwsl_info("adding indexed hdr %d (tok %d)\n", idx, tok);

	if (lws_frag_start(wsi, tok))
		return 1;

	if (idx < ARRAY_SIZE(http2_canned)) {
		p = http2_canned[idx];
		while (*p)
			if (lws_frag_append(wsi, *p++))
				return 1;
	}
	if (lws_frag_end(wsi))
		return 1;
	
	lws_dump_header(wsi, tok);

	return 0;
}

int lws_hpack_interpret(struct libwebsocket_context *context,
			struct libwebsocket *wsi, unsigned char c)
{
	unsigned int prev;
	unsigned char c1;
	int n;

	switch (wsi->u.http2.hpack) {
	case HPKS_TYPE:
		if (c & 0x80) { /* indexed header field only */
			/* just a possibly-extended integer */
			wsi->u.http2.hpack_type = HPKT_INDEXED_HDR_7;
			wsi->u.http2.header_index = c & 0x7f;
			if ((c & 0x7f) == 0x7f) {
				wsi->u.http2.hpack_len = c & 0x7f;
				wsi->u.http2.hpack_m = 0;
				wsi->u.http2.hpack = HPKS_IDX_EXT;
				break;
			}
			if (lws_add_indexed_hdr(wsi, c & 0x7f))
				return 1;
			/* stay at same state */
			break;
		}
		if (c & 0x40) { /* literal header incr idx */
			/*
			 * [possibly-extended hdr idx (6) | new literal hdr name]
			 * H + possibly-extended value length
			 * literal value
			 */
			wsi->u.http2.header_index = 0;
			if (c == 0x40) { /* literal name */
				wsi->u.http2.hpack_type = HPKT_LITERAL_HDR_VALUE_INCR;
				wsi->u.http2.value = 0;
				wsi->u.http2.hpack = HPKS_HLEN;
				break;
			}
			/* indexed name */
			wsi->u.http2.hpack_type = HPKT_INDEXED_HDR_6_VALUE_INCR;
			if ((c & 0x3f) == 0x3f) {
				wsi->u.http2.hpack_len = c & 0x3f;
				wsi->u.http2.hpack_m = 0;
				wsi->u.http2.hpack = HPKS_IDX_EXT;
				break;
			}
			wsi->u.http2.header_index = c & 0x3f;
			wsi->u.http2.value = 1;
			wsi->u.http2.hpack = HPKS_HLEN;
			break;
		}
		switch(c & 0xf0) {
		case 0x10: /* literal header never index */
		case 0: /* literal header without indexing */
			/* 
			 * follows 0x40 except 4-bit hdr idx
			 * and don't add to index
			 */
			if (c == 0) { /* literal name */
				wsi->u.http2.hpack_type = HPKT_LITERAL_HDR_VALUE;
				wsi->u.http2.hpack = HPKS_HLEN;
				wsi->u.http2.value = 0;
				break;
			}
			/* indexed name */
			wsi->u.http2.hpack_type = HPKT_INDEXED_HDR_4_VALUE;
			wsi->u.http2.header_index = 0;
			if ((c & 0xf) == 0xf) {
				wsi->u.http2.hpack_len = c & 0xf;
				wsi->u.http2.hpack_m = 0;
				wsi->u.http2.hpack = HPKS_IDX_EXT;
				break;
			}
			wsi->u.http2.header_index = c & 0xf;
			wsi->u.http2.value = 1;
			wsi->u.http2.hpack = HPKS_HLEN;
			break;

		case 0x20:
		case 0x30: /* header table size update */
			/* possibly-extended size value (5) */
			wsi->u.http2.hpack_type = HPKT_SIZE_5;
			if ((c & 0x1f) == 0x1f) {
				wsi->u.http2.hpack_len = c & 0x1f;
				wsi->u.http2.hpack_m = 0;
				wsi->u.http2.hpack = HPKS_IDX_EXT;
				break;
			}
			lws_hpack_update_table_size(wsi, c & 0x1f);
			/* stay at HPKS_TYPE state */
			break;
		}
		break;
		
	case HPKS_IDX_EXT:
		wsi->u.http2.hpack_len += (c & 0x7f) << wsi->u.http2.hpack_m;
		wsi->u.http2.hpack_m += 7;
		if (!(c & 0x80)) {
			switch (wsi->u.http2.hpack_type) {
			case HPKT_INDEXED_HDR_7:
				if (lws_add_indexed_hdr(wsi, wsi->u.http2.hpack_len))
					return 1;
				wsi->u.http2.hpack = HPKS_TYPE;
				break;
			default:
				wsi->u.http2.header_index = wsi->u.http2.hpack_len;
				wsi->u.http2.value = 1;
				wsi->u.http2.hpack = HPKS_HLEN;
				break;
			}
		}
		break;

	case HPKS_HLEN: /* [ H | 7+ ] */
		wsi->u.http2.huff = !!(c & 0x80);
		wsi->u.http2.hpack_pos = 0;
		wsi->u.http2.hpack_len = c & 0x7f;
		if (wsi->u.http2.hpack_len < 0x7f) {
pre_data:
			if (wsi->u.http2.value) {
				if (lws_frag_start(wsi,
					lws_token_from_index(wsi,
				  		wsi->u.http2.header_index)))
					return 1;
			} else
				wsi->u.hdr.parser_state = WSI_TOKEN_NAME_PART;
			wsi->u.http2.hpack = HPKS_DATA;
			break;
		}
		wsi->u.http2.hpack_m = 0;
		wsi->u.http2.hpack = HPKS_HLEN_EXT;
		break;
		
	case HPKS_HLEN_EXT:
		wsi->u.http2.hpack_len += (c & 0x7f) <<
					wsi->u.http2.hpack_m;
		wsi->u.http2.hpack_m += 7;
		if (!(c & 0x80))
			goto pre_data;

		break;

	case HPKS_DATA:
		for (n = 0; n < 8; n++) {
			if (wsi->u.http2.huff) {
				prev = wsi->u.http2.hpack_pos;
				wsi->u.http2.hpack_pos = 
					huftable_decode(
						wsi->u.http2.hpack_pos,
		     					(c >> 7) & 1);
				c <<= 1;
				if (wsi->u.http2.hpack_pos == 0xffff)
					return 1;
				if (!(wsi->u.http2.hpack_pos & 0x8000))
					continue;
				c1 = wsi->u.http2.hpack_pos & 0x7fff;
				wsi->u.http2.hpack_pos = 0;
	
				if (!c1 && prev == HUFTABLE_0x100_PREV)
					; /* EOT */
			} else {
				n = 8;
				c1 = c;
			}
			if (wsi->u.http2.value) { /* value */
				if (lws_frag_append(wsi, c1))
					return 1;
			} else { /* name */
				if (libwebsocket_parse(context, wsi, c1))
					return 1;
				
			}
		}
		if (--wsi->u.http2.hpack_len == 0) {
			n = 8;
			if (wsi->u.http2.value) {
				if (lws_frag_end(wsi))
					return 1;

				lws_dump_header(wsi, lws_token_from_index(wsi, wsi->u.http2.header_index));

				wsi->u.http2.hpack = HPKS_TYPE;
			} else { /* name */
				if (wsi->u.hdr.parser_state < WSI_TOKEN_COUNT)
					
				wsi->u.http2.value = 1;
				wsi->u.http2.hpack = HPKS_HLEN;
			}
		}
		break;
	}
	
	return 0;
}
