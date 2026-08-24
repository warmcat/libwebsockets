/* FNV-1a 64-bit content hashing (dedup / loop suppression only) */
#ifndef XIP_HASH_H
#define XIP_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t xip_fnv1a64(const void *buf, size_t len);

/* writes 16 hex digits + NUL into out (XIP_HASH_HEX bytes) */
void xip_hash_hex(const void *buf, size_t len, char *out);

#ifdef __cplusplus
}
#endif

#endif
