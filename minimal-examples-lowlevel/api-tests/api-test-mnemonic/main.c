/*
 * lws-api-test-mnemonic
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

#include <libwebsockets.h>
#include "../../../include/libwebsockets/lws-mnemonic.h"
#include <stdio.h>
#include <string.h>

struct test_vector {
	const uint8_t entropy[16];
	const char *mnemonic;
};

static const struct test_vector vectors[] = {
	{
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	},
	{
		{ 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
		  0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f },
		"legal liberty liberal lipid liberty liberal lipid liberty liberal lipid liberty list"
	},
	{
		{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 },
		"letter letter letter letter letter letter letter letter letter letter letter lactic"
	},
	{
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
	}
};

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int n, fail = 0;
	char buf[256];
	uint8_t entropy[16];

	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN;

	context = lws_create_context(&info);
	if (!context) {
		fprintf(stderr, "lws init failed\n");
		return 1;
	}

	for (n = 0; n < (int)LWS_ARRAY_SIZE(vectors); n++) {
		printf("Test Vector %d... ", n);
		if (lws_mnemonic_generate(context, vectors[n].entropy, buf, sizeof(buf))) {
			printf("FAIL (generate)\n");
			fail++;
			continue;
		}

		if (strcmp(buf, vectors[n].mnemonic)) {
			printf("FAIL (mismatch)\n  got:  '%s'\n  expected: '%s'\n", buf, vectors[n].mnemonic);
			fail++;
			continue;
		}

		if (lws_mnemonic_to_entropy(context, buf, entropy)) {
			printf("FAIL (recovery)\n");
			fail++;
			continue;
		}

		if (memcmp(entropy, vectors[n].entropy, 16)) {
			printf("FAIL (entropy mismatch)\n");
			fail++;
			continue;
		}

		printf("PASS\n");
	}

	printf("Test with random data... ");
	if (lws_get_random(context, entropy, 16) != 16) {
		printf("FAIL (get random)\n");
		fail++;
	} else {
		lws_mnemonic_generate(context, entropy, buf, sizeof(buf));
		printf("\nMnemonic: %s\n", buf);
		uint8_t recovered[16];
		if (lws_mnemonic_to_entropy(context, buf, recovered)) {
			printf("FAIL (random recovery)\n");
			fail++;
		} else if (memcmp(entropy, recovered, 16)) {
			printf("FAIL (random mismatch)\n");
			fail++;
		} else {
			printf("PASS\n");
		}
	}

	lws_context_destroy(context);

	if (fail) {
		printf("Final result: FAILED (%d failures)\n", fail);
		return 1;
	}

	printf("Final result: ALL PASSED\n");

	return 0;
}
