// Unzip library by Per Bothner and Joonas Pihlajamaa.
// See junzip.h for license and details.

#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "private-libwebsockets.h"

enum {
	ZC_SIGNATURE				= 0,
	ZC_VERSION_MADE_BY 			= 4,
	ZC_VERSION_NEEDED_TO_EXTRACT 		= 6,
	ZC_GENERAL_PURPOSE_BIT_FLAG 		= 8,
	ZC_COMPRESSION_METHOD 			= 10,
	ZC_LAST_MOD_FILE_TIME 			= 12,
	ZC_LAST_MOD_FILE_DATE 			= 14,
	ZC_CRC32 				= 16,
	ZC_COMPRESSED_SIZE 			= 20,
	ZC_UNCOMPRESSED_SIZE 			= 24,
	ZC_FILE_NAME_LENGTH 			= 28,
	ZC_EXTRA_FIELD_LENGTH 			= 30,
	ZC_FILE_COMMENT_LENGTH 			= 32,
	ZC_DISK_NUMBER_START 			= 34,
	ZC_INTERNAL_FILE_ATTRIBUTES 		= 36,
	ZC_EXTERNAL_FILE_ATTRIBUTES 		= 38,
	ZC_RELATIVE_OFFSET_OF_LOCAL_HEADER 	= 42,
	ZC_DIRECTORY_LENGTH 			= 46,

	ZE_SIGNATURE_OFFSET 			= 0,
	ZE_DESK_NUMBER 				= 4,
	ZE_CENTRAL_DIRECTORY_DISK_NUMBER 	= 6,
	ZE_NUM_ENTRIES_THIS_DISK 		= 8,
	ZE_NUM_ENTRIES 				= 10,
	ZE_CENTRAL_DIRECTORY_SIZE 		= 12,
	ZE_CENTRAL_DIRECTORY_OFFSET 		= 16,
	ZE_ZIP_COMMENT_LENGTH 			= 20,
	ZE_DIRECTORY_LENGTH 			= 22,
};

static uint16_t
get_u16(void *p)
{
	const uint8_t *c = (const uint8_t *)p;

	return (uint16_t)((c[0] | (c[1] << 8)));
}

static uint32_t
get_u32(void *p)
{
	const uint8_t *c = (const uint8_t *)p;

	return (uint32_t)((c[0] | (c[1] << 8) | (c[2] << 16) | (c[3] << 24)));
}

static int
zf_seek_set(jzfile_t *zfile, size_t offset)
{
	int new_position = offset;

	if (new_position < 0 || new_position > zfile->length)
		return -1;
	zfile->position = new_position;

	return 0;
}

static int
zf_seek_cur(jzfile_t *zfile, size_t offset)
{
	int new_position = zfile->position + offset;

	if (new_position < 0 || new_position > zfile->length)
		return -1;
	zfile->position = new_position;

	return 0;
}

static int
zf_seek_end(jzfile_t *zfile, size_t offset)
{
	int new_position = zfile->length + offset;

	if (new_position < 0 || new_position > zfile->length)
		return -1;
	zfile->position = new_position;

	return 0;
}

size_t
zf_read(jzfile_t *zfile, void *buf, size_t size)
{
	size_t avail = zfile->length - zfile->position;

	if (size > avail)
		size = avail;
	memcpy(buf, zfile->start + zfile->position, size);
	zfile->position += size;

	return size;
}

/* Read ZIP file end record. Will move within file. */
int
jzReadEndRecord(jzfile_t *zip)
{
	unsigned char *ptr = zf_current(zip);

	if (zf_seek_end(zip, -ZE_DIRECTORY_LENGTH))
		return Z_ERRNO;

	while (ptr[0] != 0x50 || ptr[1] != 0x4B || ptr[2] != 5 || ptr[3] != 6)
		if (ptr-- == zip->start)
			return Z_ERRNO;

	zip->numEntries = get_u16(ptr + ZE_NUM_ENTRIES);
	zip->centralDirectoryOffset= get_u32(ptr + ZE_CENTRAL_DIRECTORY_OFFSET);

	if (get_u16(ptr + ZE_DESK_NUMBER) ||
	    get_u16(ptr + ZE_CENTRAL_DIRECTORY_DISK_NUMBER) ||
	    zip->numEntries != get_u16(ptr + ZE_NUM_ENTRIES_THIS_DISK))
		return Z_ERRNO;

	return Z_OK;
}

/* Read ZIP file global directory. Will move within file. */
int
jzReadCentralDirectory(jzfile_t *zip, jzcb_t callback)
{
	jzfile_hdr_t h;
	int i;

	if (zf_seek_set(zip, zip->centralDirectoryOffset))
		return Z_ERRNO;

	for (i = 0; i < zip->numEntries; i++) {
		unsigned char *ptr = zf_current(zip);

		if (zf_available(zip) < ZC_DIRECTORY_LENGTH)
			return Z_ERRNO;

		zf_seek_cur(zip, ZC_DIRECTORY_LENGTH);
		if (get_u32(ptr + ZC_SIGNATURE) != 0x02014B50)
			return Z_ERRNO;

		// Construct jzfile_hdr_t from global file h
		h.compressionMethod = get_u16(ptr + ZC_COMPRESSION_METHOD);
		h.crc32 = get_u32(ptr + ZC_CRC32);
		h.compressedSize = get_u32(ptr + ZC_COMPRESSED_SIZE);
		h.uncompressedSize = get_u32(ptr + ZC_UNCOMPRESSED_SIZE);
		h.fileNameLength = get_u16(ptr + ZC_FILE_NAME_LENGTH);
		h.extraFieldLength = get_u16(ptr + ZC_EXTRA_FIELD_LENGTH);
		h.offset = get_u32(ptr + ZC_RELATIVE_OFFSET_OF_LOCAL_HEADER);

		h.fileNameStart = zf_tell(zip);
		if (zf_seek_cur(zip, h.fileNameLength + h.extraFieldLength +
				     get_u16(ptr + ZC_FILE_COMMENT_LENGTH)))
			return Z_ERRNO;

		if (!callback(zip, i, &h))
			break; // end if callback returns zero
	}

	return Z_OK;
}

int jzSeekData(jzfile_t *zip, jzfile_hdr_t *entry)
{
	size_t offset = entry->offset;

	offset += ZIP_LOCAL_FILE_HEADER_LENGTH;
	offset += entry->fileNameLength + entry->extraFieldLength;

	if (offset < 0 || offset > zip->length)
		return Z_STREAM_END;

	zip->position = offset;

	return Z_OK;
}

/* Read data from file stream, described by h, to preallocated buffer */
int
jzReadData(jzfile_t *zip, jzfile_hdr_t *h, void *buffer)
{
	unsigned char *bytes = (unsigned char *)buffer;
	long compressedLeft, uncompressedLeft;
	z_stream strm;
	int ret;

	switch (h->compressionMethod) {
	case 0: /* Store - just read it */
		if (zf_read(zip, buffer, h->uncompressedSize) <
					 h->uncompressedSize)
			return Z_ERRNO;
		break;
	case 8: /* Deflate - using zlib */
		strm.zalloc = Z_NULL;
		strm.zfree = Z_NULL;
		strm.opaque = Z_NULL;

		strm.avail_in = 0;
		strm.next_in = Z_NULL;

		/*
		 * Use inflateInit2 with negative window bits to
		 * indicate raw data
		 */
		if ((ret = inflateInit2(&strm, -MAX_WBITS)) != Z_OK)
			return ret; /* Zlib errors are negative */

		/* Inflate compressed data */
		for (compressedLeft = h->compressedSize,
				      uncompressedLeft = h->uncompressedSize;
		     compressedLeft && uncompressedLeft && ret != Z_STREAM_END;
		     compressedLeft -= strm.avail_in) {
			/* Read next chunk */
			unsigned char *ptr = zf_current(zip);

			strm.avail_in = compressedLeft;
			zf_seek_cur(zip, compressedLeft);
			if (strm.avail_in == 0) {
				inflateEnd(&strm);

				return Z_ERRNO;
			}

			strm.next_in = ptr;
			strm.avail_out = uncompressedLeft;
			strm.next_out = bytes;

			compressedLeft -= strm.avail_in;
			/* inflate will change avail_in */

			ret = inflate(&strm, Z_NO_FLUSH);

			if (ret == Z_STREAM_ERROR)
				return ret;

			switch (ret) {
			case Z_NEED_DICT:
				ret = Z_DATA_ERROR;
				/* and fall through */
			case Z_DATA_ERROR: case Z_MEM_ERROR:
				(void)inflateEnd(&strm);

				return ret;
			}

			/* bytes uncompressed */
			bytes += uncompressedLeft - strm.avail_out;
			uncompressedLeft = strm.avail_out;
		}

		inflateEnd(&strm);
		break;
	default:
		return Z_ERRNO;
	}

	return Z_OK;
}
