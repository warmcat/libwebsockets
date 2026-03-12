/*
 * lws-crypto-dnssec
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Natively integrated DNSSEC cryptography utility using lws_gencrypto.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_CURVE,
	LWS_SW_DURATION,
	LWS_SW_HASH,
	LWS_SW_KSK,
	LWS_SW_ZSK,
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_CURVE]	= { "--curve",         "Enable --curve feature" },
	[LWS_SW_DURATION]	= { "--duration",      "Enable --duration feature" },
	[LWS_SW_HASH]	= { "--hash",          "Enable --hash feature" },
	[LWS_SW_KSK]	= { "--ksk",           "Enable --ksk feature" },
	[LWS_SW_ZSK]	= { "--zsk",           "Enable --zsk feature" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

static int
do_keygen(struct lws_context *context, int argc, const char **argv)
{
	enum lws_gencrypto_kty kty = LWS_GENCRYPTO_KTY_EC;
	const char *curve = "P-256", *domain = NULL;
	const char *p;
	struct lws_jwk jwk;
	int is_ksk = 0;
	char key[32768];
	int vl = sizeof(key);

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_KSK].sw))
		is_ksk = 1;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_CURVE].sw)))
		curve = p;

	domain = argv[argc - 1];
	if (!domain || domain[0] == '-') {
		lwsl_err("keygen requires a domain name as the final argument\n");
		return 1;
	}

	lwsl_user("Generating %s for %s (Curve: %s)\n", is_ksk ? "KSK" : "ZSK", domain, curve);

	if (lws_jwk_generate(context, &jwk, kty, 0, curve)) {
		lwsl_err("lws_jwk_generate failed\n");
		return 1;
	}

	/* Force JWK metadata for easy reuse in lws-minimal-raw-dht-zone-client */
	lws_jwk_strdup_meta(&jwk, JWK_META_KTY, "EC", 2);
	lws_jwk_strdup_meta(&jwk, JWK_META_USE, "sig", 3);

	if (lws_jwk_export(&jwk, LWSJWKF_EXPORT_NOCRLF | LWSJWKF_EXPORT_PRIVATE, key, &vl) < 0) {
		lwsl_err("lws_jwk_export failed\n");
		lws_jwk_destroy(&jwk);
		return 1;
	}

	char priv_filename[256];
	lws_snprintf(priv_filename, sizeof(priv_filename), "%s.%s.private.jwk", domain, is_ksk ? "ksk" : "zsk");

	int fd = open(priv_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0600);
	if (fd >= 0) {
		write(fd, key, (size_t)strlen(key));
		close(fd);
		lwsl_notice("Wrote private JWK to %s\n", priv_filename);
	}

	/* Export standardized DNSKEY format for zone file inclusion */
	int alg = 13; /* ECDSAP256SHA256 */
	if (!strcmp(curve, "P-384")) alg = 14; /* ECDSAP384SHA384 */

	int flags = is_ksk ? 257 : 256;
	int x_len = (int)jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].len;
	int y_len = (int)jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].len;

	uint8_t *raw_key = malloc((size_t)(x_len + y_len));
	if (raw_key) {
		memcpy(raw_key, jwk.e[LWS_GENCRYPTO_EC_KEYEL_X].buf, (size_t)x_len);
		memcpy(raw_key + x_len, jwk.e[LWS_GENCRYPTO_EC_KEYEL_Y].buf, (size_t)y_len);

		int b64_len = lws_base64_size((x_len + y_len));
		char *b64_key = malloc((size_t)b64_len + 1);
		if (b64_key) {
			lws_b64_encode_string((const char *)raw_key, x_len + y_len, b64_key, b64_len);

			char pub_filename[256];
			lws_snprintf(pub_filename, sizeof(pub_filename), "%s.%s.key", domain, is_ksk ? "ksk" : "zsk");

			fd = open(pub_filename, LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0644);
			if (fd >= 0) {
				char outbuf[1024];
				int n = lws_snprintf(outbuf, sizeof(outbuf), "%s. IN DNSKEY %d 3 %d %s\n", domain, flags, alg, b64_key);
				write(fd, outbuf, (size_t)n);
				close(fd);
				lwsl_notice("Wrote public DNSKEY to %s\n", pub_filename);
			}
			free(b64_key);
		}
		free(raw_key);
	}

	lws_jwk_destroy(&jwk);
	return 0;
}

static int
name_to_wire(const char *name, uint8_t *wire)
{
	const char *p = name;
	uint8_t *wp = wire;
	uint8_t *len_ptr = wp++;
	int l = 0;

	while (*p) {
		if (*p == '.') {
			*len_ptr = (uint8_t)l;
			len_ptr = wp++;
			l = 0;
		} else {
			*wp++ = (uint8_t)((*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p);
			l++;
		}
		p++;
	}
	*len_ptr = (uint8_t)l;
	if (l > 0)
		*wp++ = 0;
	return (int)(wp - wire);
}

static uint16_t
calc_keytag(const uint8_t *rdata, int rdata_len)
{
	uint32_t ac = 0;
	int i;
	for (i = 0; i < rdata_len; i++)
		ac += (i & 1) ? (uint32_t)rdata[i] : ((uint32_t)rdata[i] << 8);
	ac += (ac >> 16) & 0xFFFF;
	return (uint16_t)(ac & 0xFFFF);
}

static int
do_dsfromkey(struct lws_context *context, int argc, const char **argv)
{
	const char *key_file = argv[argc - 1];
	enum lws_genhash_types hash_idx = LWS_GENHASH_TYPE_SHA256;
	int digest_type = 2; // SHA-256
	const char *p;

	if (!key_file || key_file[0] == '-') {
		lwsl_err("dsfromkey requires a .key file\n");
		return 1;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_HASH].sw))) {
		if (!strcmp(p, "SHA384")) {
			hash_idx = LWS_GENHASH_TYPE_SHA384;
			digest_type = 4;
		} else if (!strcmp(p, "SHA512")) {
			hash_idx = LWS_GENHASH_TYPE_SHA512;
			digest_type = 4; // BIND maps 384 as type 4. 512 has no standard IANA DS digest type yet, using 4.
		}
	}

	int fd = open(key_file, O_RDONLY);
	if (fd < 0) {
		lwsl_err("Failed to open %s\n", key_file);
		return 1;
	}

	char buf[8192];
	int n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) return 1;
	buf[n] = '\0';

	char domain[256] = {0};
	int flags = 0, proto = 0, alg = 0;
	char b64[8192];
	if (sscanf(buf, "%255s IN DNSKEY %d %d %d %8191s", domain, &flags, &proto, &alg, b64) != 5) {
		lwsl_err("Failed to parse DNSKEY record\n");
		return 1;
	}

	uint8_t rdata[4096];
	rdata[0] = (uint8_t)((flags >> 8) & 0xff);
	rdata[1] = (uint8_t)(flags & 0xff);
	rdata[2] = (uint8_t)proto;
	rdata[3] = (uint8_t)alg;

	int pub_len = lws_b64_decode_string_len(b64, (int)strlen(b64), (char *)rdata + 4, sizeof(rdata) - 4);
	if (pub_len < 0) {
		lwsl_err("Failed to decode base64 public key\n");
		return 1;
	}

	int rdata_len = 4 + pub_len;
	uint16_t keytag = calc_keytag(rdata, rdata_len);

	uint8_t payload[8192];
	int name_len = name_to_wire(domain, payload);
	memcpy(payload + name_len, rdata, (size_t)rdata_len);
	int payload_len = name_len + rdata_len;

	struct lws_genhash_ctx hash_ctx;
	uint8_t digest[64];

	if (lws_genhash_init(&hash_ctx, hash_idx)) {
		lwsl_err("lws_genhash_init failed\n");
		return 1;
	}
	if (lws_genhash_update(&hash_ctx, payload, (size_t)payload_len)) {
		lwsl_err("lws_genhash_update failed\n");
		lws_genhash_destroy(&hash_ctx, NULL);
		return 1;
	}
	lws_genhash_destroy(&hash_ctx, digest);

	int d_len = (int)lws_genhash_size(hash_idx);

	printf("%s IN DS %u %d %d ", domain, keytag, alg, digest_type);
	for (int i = 0; i < d_len; i++) {
		printf("%02X", digest[i]);
	}
	printf("\n");

	return 0;
}

static int
do_signzone(struct lws_context *context, int argc, const char **argv)
{
	struct lws_auth_dns_sign_info info;
	const char *p;

	memset(&info, 0, sizeof(info));
	info.cx = context;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_ZSK].sw)))
		info.zsk_jwk_filepath = p;
	else {
		lwsl_err("signzone requires --zsk myzone.zsk.private.jwk\n");
		return 1;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_KSK].sw)))
		info.ksk_jwk_filepath = p;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_DURATION].sw)))
		info.sign_validity_duration = (uint32_t)atoi(p);

	if (argc < 4 || argv[argc - 3][0] == '-' || argv[argc - 2][0] == '-' || argv[argc - 1][0] == '-') {
		lwsl_err("Usage: signzone --zsk ... <in.zone> <out.zone> <out.jws>\n");
		return 1;
	}

	info.input_filepath = argv[argc - 3];
	info.output_filepath = argv[argc - 2];
	info.jws_filepath = argv[argc - 1];

	if (lws_auth_dns_sign_zone(&info)) {
		lwsl_err("lws_auth_dns_sign_zone failed\n");
		return 1;
	}

	return 0;
}

int main(int argc, const char **argv)
{
	int result = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct lws_context_creation_info info;
	struct lws_context *context;
	const char *p;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}


	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS DNSSEC Crypto Utility\n");

	if (argc < 2) {
		lwsl_err("Usage: lws-crypto-dnssec <keygen|dsfromkey|signzone> [args...]\n");
		return 1;
	}

	memset(&info, 0, sizeof info);
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = 0;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	const char *mode = argv[1];

	if (!strcmp(mode, "keygen"))
		result = do_keygen(context, argc, argv);
	else if (!strcmp(mode, "dsfromkey"))
		result = do_dsfromkey(context, argc, argv);
	else if (!strcmp(mode, "signzone"))
		result = do_signzone(context, argc, argv);
	else {
		lwsl_err("Unknown mode: %s. Use keygen, dsfromkey, or signzone.\n", mode);
		result = 1;
	}

	lws_context_destroy(context);
	return result;
}
