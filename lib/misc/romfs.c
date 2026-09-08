/*
 * Copyright (C) 2017 National Institute of Advanced Industrial Science
 *                    and Technology (AIST)
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of AIST nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "romfs.h"
#if defined(LWS_WITH_ESP32)
#include <esp_flash.h>
#include "spi_flash_mmap.h"
#endif

#define RFS_STRING_MAX 96

/* how many symlinks we are willing to chase before calling it a loop */
#define RFS_MAX_SYMLINK_HOPS 8

static u32_be_t cache[(RFS_STRING_MAX + 32) / 4];
static romfs_inode_t ci = (romfs_inode_t)cache;
static romfs_t cr = (romfs_t)cache;

static void
set_cache(romfs_inode_t inode, size_t len)
{
#if defined(LWS_WITH_ESP32)
//	spi_flash_read((uint32_t)inode, cache, len);
	// esp_err_t esp_flash_read(esp_flash_t *chip, void *buffer, uint32_t address, uint32_t length);

	if (len > sizeof(cache))
		len = sizeof(cache);

	/*
	 * cache[] is the RAM destination and inode the flash address we are
	 * reading from, ie, (chip, buffer, address, length)
	 */

	esp_flash_read(NULL, cache, (uint32_t)(uintptr_t)inode, (uint32_t)len);
#else
	(void)inode;
	(void)len;
#endif
}

/*
 * Everything in the image (inode offsets, dir_start, next, name lengths, file
 * sizes) comes from the image itself and so is untrusted... romfs_avail()
 * reports how many bytes remain from p to the end of the image, or 0 if p is
 * not inside it at all.  Every derived pointer is checked with it before it
 * is dereferenced.
 */

static size_t
romfs_avail(romfs_t romfs, size_t size, const void *p)
{
	const uint8_t *base = (const uint8_t *)romfs, *q = (const uint8_t *)p;

	if (q < base)
		return 0;

	if ((size_t)(q - base) > size)
		return 0;

	return size - (size_t)(q - base);
}

/* read one inode into cache[], nonzero if it isn't wholly inside the image */

static int
romfs_cache_inode(romfs_t romfs, size_t size, romfs_inode_t i)
{
	if (romfs_avail(romfs, size, i) < sizeof(*i))
		return 1;

	set_cache(i, sizeof(*i));

	return 0;
}

/*
 * read the NUL-terminated name at p into cache[], clipped to what is actually
 * left in the image, and terminate it ourselves so the strlen() below cannot
 * run past what we read
 */

static int
romfs_cache_name(romfs_t romfs, size_t size, const void *p)
{
	size_t avail = romfs_avail(romfs, size, p);

	if (!avail)
		return 1;

	if (avail > RFS_STRING_MAX)
		avail = RFS_STRING_MAX;

	set_cache((romfs_inode_t)p, avail);
	((char *)cache)[avail] = '\0';

	return 0;
}

static uint32_t
untohl(const u32_be_t be)
{
	return ((be >> 24) & 0xff) |
	       ((be >> 16) & 0xff) << 8 |
	       ((be >> 8) & 0xff) << 16 |
	       (be & 0xff) << 24;
}
static romfs_inode_t
romfs_lookup(romfs_t romfs, size_t size, romfs_inode_t start, const char *path,
	     int hops);

static int
plus_padding(romfs_t romfs, size_t size, const uint8_t *s)
{
	int n;

	if (romfs_cache_name(romfs, size, s))
		return -1;

	n = (int)strlen((const char *)cache);

	if (!(n & 15))
		n += 0x10;

	return (n + 15) & ~15;
}

static romfs_inode_t
skip_and_pad(romfs_t romfs, size_t size, romfs_inode_t ri)
{
	const uint8_t *p = ((const uint8_t *)ri) + sizeof(*ri);
	int n;

	if (romfs_avail(romfs, size, ri) < sizeof(*ri))
		return NULL;

	n = plus_padding(romfs, size, p);
	if (n < 0)
		return NULL;

	if (!romfs_avail(romfs, size, p + n))
		return NULL;

	return (romfs_inode_t)(p + n);
}

size_t
romfs_mount_check(romfs_t romfs)
{
	set_cache((romfs_inode_t)romfs, sizeof(*romfs));

	if (cr->magic1 != 0x6d6f722d ||
	    cr->magic2 != 0x2d736631)
		return 0;

	return untohl(cr->size);
}

static romfs_inode_t
romfs_symlink(romfs_t romfs, size_t size, romfs_inode_t level, romfs_inode_t i,
	      int hops)
{
	const char *p = (const char *)skip_and_pad(romfs, size, i);

	if (!p)
		return NULL;

	/*
	 * a symlink cycle in the image would recurse here forever without
	 * this
	 */

	if (hops >= RFS_MAX_SYMLINK_HOPS)
		return NULL;

	/* skip_and_pad() confirmed there is at least one byte at p */

	if (*p == '/') {
		level = skip_and_pad(romfs, size, (romfs_inode_t)romfs);
		if (!level)
			return NULL;
		p++;
	}

	return romfs_lookup(romfs, size, level, p, hops + 1);
}

static romfs_inode_t
dir_link(romfs_t romfs, size_t size, romfs_inode_t i)
{
	romfs_inode_t r;

	if (romfs_cache_inode(romfs, size, i))
		return NULL;

	r = (romfs_inode_t)((const uint8_t *)romfs + untohl(ci->dir_start));

	if (romfs_avail(romfs, size, r) < sizeof(*r))
		return NULL;

	return r;
}

static romfs_inode_t
romfs_lookup(romfs_t romfs, size_t size, romfs_inode_t start, const char *path,
	     int hops)
{
	romfs_inode_t level, i = start, i_in;
	size_t budget = (size / sizeof(struct romfs_i)) + 1;
	const char *p, *cp;
	uint32_t next_be;

	if (!i)
		return NULL;

	if (start == (romfs_inode_t)romfs) {
		i = skip_and_pad(romfs, size, (romfs_inode_t)romfs);
		if (!i)
			return NULL;
	}
	level = i;
	while (i != (romfs_inode_t)romfs) {
		const char *n = ((const char *)i) + sizeof(*i);

		/*
		 * the next chain is image-supplied and can be a cycle of any
		 * length... only self-loops were caught below, so also cap the
		 * total number of hops at the most inodes the image can hold
		 */

		if (!budget--)
			return NULL;

		p = path;
		i_in = i;

		if (romfs_cache_inode(romfs, size, i))
			return NULL;
		next_be = ci->next;

		cp = (const char *)cache;
		if (romfs_cache_name(romfs, size, n))
			return NULL;

		while (*p && *p != '/' && *cp && *p == *cp &&
		       (p - path) < RFS_STRING_MAX) {
			p++;
			n++;
			cp++;
		}

		while (*p == '/' && p[1] == '/')
			p++;

		if (!*cp && (!*p || *p == '/') &&
		    (untohl(next_be) & 7) == RFST_HARDLINK) {
			romfs_inode_t r;

			if (romfs_cache_inode(romfs, size, i))
				return NULL;

			r = (romfs_inode_t)((const uint8_t *)romfs +
					    (untohl(ci->dir_start) & ~15u));

			if (romfs_avail(romfs, size, r) < sizeof(*r))
				return NULL;

			return r;
		}

		if (!*p && !*cp) {
			if (romfs_cache_inode(romfs, size, i))
				return NULL;
			if ((untohl(ci->next) & 7) == RFST_SYMLINK) {
				i = romfs_symlink(romfs, size, level, i, hops);
				if (!i)
					return NULL;
				continue;
			}
			return i;
		}

		if (!*p && *cp == '/')
			return NULL;

		while (*p == '/' && p[1] == '/')
			p++;

		if (*p == '/' && !*cp) {
			if (romfs_cache_inode(romfs, size, i))
				return NULL;
			switch (untohl(ci->next) & 7) {
			case RFST_SYMLINK:
				i = romfs_symlink(romfs, size, level, i, hops);
				if (!i)
					return NULL;
				i = dir_link(romfs, size, i);
				if (!i)
					return NULL;
				while (*path != '/' && *path)
					path++;
				if (!*path)
					return NULL;
				path++;
				continue;
			case RFST_DIR:
				path = p + 1;
				i = dir_link(romfs, size, i);
				break;
			default:
				path = p + 1;
				i = skip_and_pad(romfs, size, i);
				break;
			}
			if (!i)
				return NULL;
			level = i;
			continue;
		}

		if (romfs_cache_inode(romfs, size, i))
			return NULL;
		if (!(untohl(ci->next) & ~15u))
			return NULL;

		i = (romfs_inode_t)((const uint8_t *)romfs +
				    (untohl(ci->next) & ~15u));
		if (i == i_in)
			return NULL;

		if (romfs_avail(romfs, size, i) < sizeof(*i))
			return NULL;
	}

	return NULL;
}

const void *
romfs_get_info(romfs_t romfs, const char *path, size_t *len, size_t *csum)
{
	const void *data;
	romfs_inode_t i;
	size_t size, l;

	size = romfs_mount_check(romfs);
	if (!size)
		return NULL;

	if (*path == '/')
		path++;

	i = romfs_lookup(romfs, size, (romfs_inode_t)romfs, path, 0);

	if (!i)
		return NULL;

	if (romfs_cache_inode(romfs, size, i))
		return NULL;

	l = untohl(ci->size);

	data = (const void *)skip_and_pad(romfs, size, i);
	if (!data)
		return NULL;

	/* the length came out of the image too, it must fit in the image */

	if (romfs_avail(romfs, size, data) < l)
		return NULL;

	*len = l;
	if (csum)
		*csum = untohl(ci->checksum);

	return data;
}
