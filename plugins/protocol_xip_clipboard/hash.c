#include "hash.h"

uint64_t
xip_fnv1a64(const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;
	uint64_t h = 0xcbf29ce484222325ULL; /* FNV-1a 64 offset basis */

	while (len--)
		h = (h ^ *p++) * 0x100000001b3ULL; /* FNV-1a 64 prime */

	return h;
}

void
xip_hash_hex(const void *buf, size_t len, char *out)
{
	static const char hex[] = "0123456789abcdef";
	uint64_t h = xip_fnv1a64(buf, len);
	int i;

	for (i = 15; i >= 0; i--) {
		out[i] = hex[h & 0xf];
		h >>= 4;
	}
	out[16] = '\0';
}
