/**
 * Unzip library by Per Bothner.
 * Loosely based on Joonas Pihlajamaa's JUnzip.
 * Released into public domain. https://github.com/jokkebk/JUnzip
 */

#ifndef __JUNZIP_H
#define __JUNZIP_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdint.h>

// If you don't have stdint.h, the following two lines should work for most 32/64 bit systems
// typedef unsigned int uint32_t;
// typedef unsigned short uint16_t;

typedef struct JZFile JZFile;

struct JZFile {
    unsigned char *start;
    off_t length;
    long position;
    int numEntries;
    uint32_t centralDirectoryOffset;
};

#define zf_tell(ZF) ((ZF)->position)
#define zf_available(ZF) ((ZF)->length - (ZF)->position)
#define zf_current(ZF) ((ZF)->start + (ZF)->position)

#define ZIP_LOCAL_FILE_HEADER_LENGTH 30

typedef struct {
    uint16_t compressionMethod;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    long fileNameStart;
    uint16_t fileNameLength;
    uint16_t extraFieldLength; // unsupported
    uint32_t offset;
} JZFileHeader;

// Callback prototype for central and local file record reading functions
typedef int (*JZRecordCallback)(JZFile *zip, int index, JZFileHeader *header);

// Read ZIP file end record. Will move within file.
int jzReadEndRecord(JZFile *zip);

// Read ZIP file global directory. Will move within file.
// Callback is called for each record, until callback returns zero
int jzReadCentralDirectory(JZFile *zip, JZRecordCallback callback);

  // See to the start of the actual data of the given entry.
int jzSeekData(JZFile *zip, JZFileHeader *header);

// Read data from file stream, described by header, to preallocated buffer
// Return value is zlib coded, e.g. Z_OK, or error code
int jzReadData(JZFile *zip, JZFileHeader *header, void *buffer);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif
