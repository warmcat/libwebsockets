// Unzip library by Per Bothner and Joonas Pihlajamaa.
// See junzip.h for license and details.

#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include "junzip.h"

#define ZIP_CENTRAL_SIGNATURE 0
#define ZIP_CENTRAL_VERSION_MADE_BY 4
#define ZIP_CENTRAL_VERSION_NEEDED_TO_EXTRACT 6
#define ZIP_CENTRAL_GENERAL_PURPOSE_BIT_FLAG 8
#define ZIP_CENTRAL_COMPRESSION_METHOD 10
#define ZIP_CENTRAL_LAST_MOD_FILE_TIME 12
#define ZIP_CENTRAL_LAST_MOD_FILE_DATE 14
#define ZIP_CENTRAL_CRC32 16
#define ZIP_CENTRAL_COMPRESSED_SIZE 20
#define ZIP_CENTRAL_UNCOMPRESSED_SIZE 24
#define ZIP_CENTRAL_FILE_NAME_LENGTH 28
#define ZIP_CENTRAL_EXTRA_FIELD_LENGTH 30
#define ZIP_CENTRAL_FILE_COMMENT_LENGTH 32
#define ZIP_CENTRAL_DISK_NUMBER_START 34
#define ZIP_CENTRAL_INTERNAL_FILE_ATTRIBUTES 36
#define ZIP_CENTRAL_EXTERNAL_FILE_ATTRIBUTES 38
#define ZIP_CENTRAL_RELATIVE_OFFSET_OF_LOCAL_HEADER 42
#define ZIP_CENTRAL_DIRECTORY_LENGTH 46

#define ZIP_END_SIGNATURE_OFFSET 0
#define ZIP_END_DESK_NUMBER 4
#define ZIP_END_CENTRAL_DIRECTORY_DISK_NUMBER 6
#define ZIP_END_NUM_ENTRIES_THIS_DISK 8
#define ZIP_END_NUM_ENTRIES 10
#define ZIP_END_CENTRAL_DIRECTORY_SIZE 12
#define ZIP_END_CENTRAL_DIRECTORY_OFFSET 16
#define ZIP_END_ZIP_COMMENT_LENGTH 20
#define ZIP_END_DIRECTORY_LENGTH 22

#define get_u16(PTR) ((PTR)[0] | ((PTR)[1] << 8))
#define get_u32(PTR) ((PTR)[0] | ((PTR)[1]<<8) | ((PTR)[2]<<16) | ((PTR)[3]<<24))

static int
zf_seek_set(JZFile *zfile, size_t offset)
{
    int new_position = offset;
    if (new_position < 0 || new_position > zfile->length)
        return -1;
    zfile->position = new_position;
    return 0;
}

static int
zf_seek_cur(JZFile *zfile, size_t offset)
{
    int new_position = zfile->position + offset;
    if (new_position < 0 || new_position > zfile->length)
        return -1;
    zfile->position = new_position;
    return 0;
}

static int
zf_seek_end(JZFile *zfile, size_t offset)
{
    int new_position = zfile->length + offset;
    if (new_position < 0 || new_position > zfile->length)
        return -1;
    zfile->position = new_position;
    return 0;
}

size_t zf_read(JZFile *zfile, void *buf, size_t size)
{
    size_t avail = zfile->length - zfile->position;
    if (size > avail)
        size = avail;
    memcpy(buf, zfile->start + zfile->position, size);
    zfile->position += size;
    return size;
}

// Read ZIP file end record. Will move within file.
int jzReadEndRecord(JZFile *zip) {
    long fileSize, readBytes, i;

    if(zf_seek_end(zip, -ZIP_END_DIRECTORY_LENGTH)) {
        return Z_ERRNO;
    }

    unsigned char *ptr = zf_current(zip);
    while (ptr[0] != 0x50 || ptr[1] != 0x4B || ptr[2] != 0x05 || ptr[3] != 0x06) {
        if (ptr == zip->start) {
            return Z_ERRNO;
        }
        ptr--;
    }
    zip->numEntries = get_u16(ptr + ZIP_END_NUM_ENTRIES);
    zip->centralDirectoryOffset= get_u32(ptr + ZIP_END_CENTRAL_DIRECTORY_OFFSET);
    if (get_u16(ptr + ZIP_END_DESK_NUMBER)
        || get_u16(ptr + ZIP_END_CENTRAL_DIRECTORY_DISK_NUMBER)
        || zip->numEntries != get_u16(ptr + ZIP_END_NUM_ENTRIES_THIS_DISK)) {
        return Z_ERRNO;
    }

    return Z_OK;
}

// Read ZIP file global directory. Will move within file.
int jzReadCentralDirectory(JZFile *zip, JZRecordCallback callback) {
    JZFileHeader header;
    int i;

    if(zf_seek_set(zip, zip->centralDirectoryOffset)) {
        return Z_ERRNO;
    }

    for(i=0; i < zip->numEntries; i++) {
        unsigned char *ptr = zf_current(zip);
        if (zf_available(zip) < ZIP_CENTRAL_DIRECTORY_LENGTH) {
            return Z_ERRNO;
        }
        zf_seek_cur(zip, ZIP_CENTRAL_DIRECTORY_LENGTH);
        if (get_u32(ptr + ZIP_CENTRAL_SIGNATURE) != 0x02014B50) {
            return Z_ERRNO;
        }
        // Construct JZFileHeader from global file header
        header.compressionMethod = get_u16(ptr + ZIP_CENTRAL_COMPRESSION_METHOD);
        header.crc32 = get_u32(ptr + ZIP_CENTRAL_CRC32);
        header.compressedSize = get_u32(ptr + ZIP_CENTRAL_COMPRESSED_SIZE);
        header.uncompressedSize = get_u32(ptr + ZIP_CENTRAL_UNCOMPRESSED_SIZE);
        header.fileNameLength = get_u16(ptr + ZIP_CENTRAL_FILE_NAME_LENGTH);
        header.extraFieldLength = get_u16(ptr + ZIP_CENTRAL_EXTRA_FIELD_LENGTH);
        header.offset = get_u32(ptr + ZIP_CENTRAL_RELATIVE_OFFSET_OF_LOCAL_HEADER);

        header.fileNameStart = zf_tell(zip);
        if (zf_seek_cur(zip, header.fileNameLength + header.extraFieldLength + get_u16(ptr + ZIP_CENTRAL_FILE_COMMENT_LENGTH))) {
            return Z_ERRNO;
        }

        if(!callback(zip, i, &header))
            break; // end if callback returns zero
    }

    return Z_OK;
}

int jzSeekData(JZFile *zip, JZFileHeader *entry) {
    size_t offset = entry->offset;
    offset += ZIP_LOCAL_FILE_HEADER_LENGTH;
    offset += entry->fileNameLength + entry->extraFieldLength;
    if (offset < 0 || offset > zip->length)
        return Z_STREAM_END;
    zip->position = offset;
    return Z_OK;
}

// Read data from file stream, described by header, to preallocated buffer
int jzReadData(JZFile *zip, JZFileHeader *header, void *buffer) {
    unsigned char *bytes = (unsigned char *)buffer; // cast
    long compressedLeft, uncompressedLeft;
    z_stream strm;
    int ret;

    if(header->compressionMethod == 0) { // Store - just read it
        if (zf_read(zip, buffer, header->uncompressedSize) <
                header->uncompressedSize)
            return Z_ERRNO;
    } else if (header->compressionMethod == 8) { // Deflate - using zlib
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;

        strm.avail_in = 0;
        strm.next_in = Z_NULL;

        // Use inflateInit2 with negative window bits to indicate raw data
        if ((ret = inflateInit2(&strm, -MAX_WBITS)) != Z_OK)
            return ret; // Zlib errors are negative

        // Inflate compressed data
        for (compressedLeft = header->compressedSize,
                uncompressedLeft = header->uncompressedSize;
                compressedLeft && uncompressedLeft && ret != Z_STREAM_END;
                compressedLeft -= strm.avail_in) {
            // Read next chunk
            unsigned char *ptr = zf_current(zip);
            strm.avail_in = compressedLeft;
            zf_seek_cur(zip, compressedLeft);
            if(strm.avail_in == 0) {
                inflateEnd(&strm);
                return Z_ERRNO;
            }

            strm.next_in = ptr;
            strm.avail_out = uncompressedLeft;
            strm.next_out = bytes;

            compressedLeft -= strm.avail_in; // inflate will change avail_in

            ret = inflate(&strm, Z_NO_FLUSH);

            if(ret == Z_STREAM_ERROR) return ret; // shouldn't happen

            switch (ret) {
                case Z_NEED_DICT:
                    ret = Z_DATA_ERROR;     /* and fall through */
                case Z_DATA_ERROR: case Z_MEM_ERROR:
                    (void)inflateEnd(&strm);
                    return ret;
            }

            bytes += uncompressedLeft - strm.avail_out; // bytes uncompressed
            uncompressedLeft = strm.avail_out;
        }

        inflateEnd(&strm);
    } else {
        return Z_ERRNO;
    }

    return Z_OK;
}
