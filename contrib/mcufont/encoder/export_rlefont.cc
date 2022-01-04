#include "export_rlefont.hh"
#include <vector>
#include <iomanip>
#include <map>
#include <set>
#include <algorithm>
#include <string>
#include <cctype>
#include "exporttools.hh"
#include "ccfixes.hh"

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#define RLEFONT_FORMAT_VERSION		5
#define RELFONT_HDR_LEN			64
#define RELFONT_RANGE_HDR_LEN		16

#define MAX_RANGES			32

enum {
	MCUFO_MAGIC			= 0,
	MCUFO_FLAGS_VER			= 4,
	MCUFO_FOFS_FULLNAME		= 8,
	MCUFO_FOFS_NAME			= 0xc,
	MCUFO_FOFS_DICT_DATA		= 0x10,
	MCUFO_SIZE_DICT_DATA		= 0x14,
	MCUFO_FOFS_DICT_OFS		= 0x18,
	MCUFO_COUNT_RLE_DICT		= 0x1C,
	MCUFO_COUNT_REF_RLE_DICT	= 0x20,
	MCUFO_FOFS_CHAR_RANGE_TABLES	= 0x24,
	MCUFO_COUNT_CHAR_RANGE_TABLES	= 0x28,
	MCUFO_UNICODE_FALLBACK		= 0x2C,

	MCUFO16_WIDTH			= 0x30,
	MCUFO16_HEIGHT			= 0x32,
	MCUFO16_MIN_X_ADV		= 0x34,
	MCUFO16_MAX_X_ADV		= 0x36,
	MCUFO16_BASELINE_X		= 0x38,
	MCUFO16_BASELINE_Y		= 0x3a,
	MCUFO16_LINE_HEIGHT		= 0x3c,

	MCUFO16_RESERVED		= 0x3e
};

namespace mcufont {
namespace rlefont {

int fd, fd1;
uint8_t hdr[RELFONT_HDR_LEN];
uint32_t fofs_range_ofs[32], fofs_range_data[32];

static void
out32(uint8_t *b, uint32_t u)
{
	*b++ = (uint8_t)((u >> 24) & 0xff);
	*b++ = (uint8_t)((u >> 16) & 0xff);
	*b++ = (uint8_t)((u >> 8) & 0xff);
	*b++ = (uint8_t)((u) & 0xff);
}

static uint32_t
in32(const uint8_t *b)
{
	return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

static void
out16(uint8_t *b, uint16_t u)
{
	*b++ = (uint8_t)((u >> 8) & 0xff);
	*b++ = (uint8_t)((u) & 0xff);
}

void write_source(std::ostream &out, std::string _name, const DataFile &datafile)
{
    std::string name = filename_to_identifier(_name), n1 = _name;
    std::unique_ptr<encoded_font_t> encoded = encode_font(datafile, false);
    std::vector<char_range_t> ranges;
    uint32_t filesize, cri;
    char line[200];
    size_t m, cc, ao = 0;

    auto get_glyph_size = [&encoded](size_t i)
    {
        return encoded->glyphs[i].size() + 1; // +1 byte for glyph width
    };

    std::cout << "Writing " + n1 + '\n';
    fd = open(n1.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
	    fprintf(stderr, "Failed to open %s\n", n1.c_str());
	    return;
    }

    /* placeholder for header */
    if (write(fd, hdr, RELFONT_HDR_LEN) < 0)
	    goto fail;

    hdr[MCUFO_MAGIC] = 'M';
    hdr[MCUFO_MAGIC + 1] = 'C';
    hdr[MCUFO_MAGIC + 2] = 'U';
    hdr[MCUFO_MAGIC + 3] = 'F';
    out32(&hdr[MCUFO_FLAGS_VER], (datafile.GetFontInfo().flags << 8) | RLEFONT_FORMAT_VERSION);
    out32(&hdr[MCUFO_FOFS_FULLNAME], (uint32_t)lseek(fd, 0, SEEK_END));
    if (write(fd, datafile.GetFontInfo().name.c_str(),
	      strlen(datafile.GetFontInfo().name.c_str()) + 1) < 0)
	    goto fail;
    out32(&hdr[MCUFO_FOFS_NAME], (uint32_t)lseek(fd, 0, SEEK_END));
    if (write(fd, name.c_str(), strlen(name.c_str()) + 1) < 0)
	    goto fail;
    out32(&hdr[MCUFO_FOFS_DICT_DATA], (uint32_t)lseek(fd, 0, SEEK_END));

    /*
     * Dictionaries
     */

    {
        std::vector<unsigned> offsets;
        std::vector<unsigned> data;
        uint8_t u;

        for (const encoded_font_t::rlestring_t &r : encoded->rle_dictionary)
        {
            offsets.push_back(data.size());
            data.insert(data.end(), r.begin(), r.end());
        }

        for (const encoded_font_t::refstring_t &r : encoded->ref_dictionary)
        {
            offsets.push_back(data.size());
            data.insert(data.end(), r.begin(), r.end());
        }
        offsets.push_back(data.size());

        out32(&hdr[MCUFO_SIZE_DICT_DATA], (uint32_t)data.size());

        for (size_t i = 0; i < data.size(); i++) {
    	    u = data.at(i);
    	    if (write(fd, &u, 1) < 0)
    		    goto fail;
        }

        out32(&hdr[MCUFO_FOFS_DICT_OFS], (uint32_t)lseek(fd, 0, SEEK_END));

        for (size_t i = 0; i < offsets.size(); i++) {
    	    uint16_t u = offsets.at(i);
    	    uint8_t b[2];

    	    b[0] = (uint8_t)(u >> 8);
    	    b[1] = (uint8_t)(u & 0xff);
    	    if (write(fd, b, 2) < 0)
    		    goto fail;
        }

        out32(&hdr[MCUFO_COUNT_RLE_DICT], (uint32_t)encoded->rle_dictionary.size());
        out32(&hdr[MCUFO_COUNT_REF_RLE_DICT], (uint32_t)(encoded->rle_dictionary.size() +
        			     encoded->ref_dictionary.size()));
    }

    /*
     * Character ranges
     */

    cri = (uint32_t)lseek(fd, 0, SEEK_END);

    ranges = compute_char_ranges(datafile, get_glyph_size, 65536, 16);

    for (size_t i = 0; i < ranges.size(); i++)
    {
        std::vector<unsigned> offsets;
        std::vector<unsigned> data;
        std::map<size_t, unsigned> already_encoded;

        for (int glyph_index : ranges.at(i).glyph_indices)
        {
            if (already_encoded.count(glyph_index))
            {
                offsets.push_back(already_encoded[glyph_index]);
            }
            else
            {
                encoded_font_t::refstring_t r;
                int width = 0;

                if (glyph_index >= 0)
                {
                    r = encoded->glyphs[glyph_index];
                    width = datafile.GetGlyphEntry(glyph_index).width;
                }

                offsets.push_back(data.size());
                already_encoded[glyph_index] = data.size();

                data.push_back(width);
                data.insert(data.end(), r.begin(), r.end());
            }
        }

        fofs_range_ofs[i] = (uint32_t)lseek(fd, 0, SEEK_END);

        for (size_t n = 0; n < offsets.size(); n++) {
        	    uint16_t u = offsets.at(n);
        	    uint8_t b[2];

        	    b[0] = (uint8_t)(u >> 8);
        	    b[1] = (uint8_t)(u & 0xff);
        	    write(fd, b, 2);
        }

        fofs_range_data[i] = (uint32_t)lseek(fd, 0, SEEK_END);

        for (size_t n = 0; n < data.size(); n++) {
    	    uint8_t u;

        	    u = data.at(n);
        	    if (write(fd, &u, 1) < 0)
        		    goto fail;
        }
    }

    out32(&hdr[MCUFO_FOFS_CHAR_RANGE_TABLES], (uint32_t)lseek(fd, 0, SEEK_END));
    out32(&hdr[MCUFO_COUNT_CHAR_RANGE_TABLES], ranges.size());

    for (size_t i = 0; i < ranges.size(); i++) {
	    uint8_t rb[16];

	    out32(&rb[0], (uint32_t)ranges.at(i).first_char);
	    out32(&rb[4], (uint32_t)ranges.at(i).char_count);
	    out32(&rb[8], (uint32_t)fofs_range_ofs[i]);
	    out32(&rb[12], (uint32_t)fofs_range_data[i]);

	    if (write(fd, rb, 16) < 0)
		    goto fail;
    }

    out32(&hdr[MCUFO_UNICODE_FALLBACK], select_fallback_char(datafile));
    out16(&hdr[MCUFO16_WIDTH], datafile.GetFontInfo().max_width);
    out16(&hdr[MCUFO16_HEIGHT], datafile.GetFontInfo().max_height);
    out16(&hdr[MCUFO16_MIN_X_ADV], get_min_x_advance(datafile));
    out16(&hdr[MCUFO16_MAX_X_ADV], get_max_x_advance(datafile));
    out16(&hdr[MCUFO16_BASELINE_X], datafile.GetFontInfo().baseline_x);
    out16(&hdr[MCUFO16_BASELINE_Y], datafile.GetFontInfo().baseline_y);
    out16(&hdr[MCUFO16_LINE_HEIGHT], datafile.GetFontInfo().line_height);
    out16(&hdr[MCUFO16_RESERVED], 0);

    filesize = (uint32_t)lseek(fd, 0, SEEK_END);

    if (lseek(fd, 0, SEEK_SET) < 0)
	    goto fail;
    if (write(fd, hdr, RELFONT_HDR_LEN) < 0)
	    goto fail;

    if (lseek(fd, 0, SEEK_SET) < 0)
	    goto fail;

    n1.append(".h");
    std::cout << "Writing " + n1 + '\n';
        fd1 = open(n1.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd1 < 0) {
    	    fprintf(stderr, "Failed to open %s\n", n1.c_str());
    	    goto fail;
        }

   cc = 0;
   for (size_t i = 0; i < ranges.size(); i++)
	  cc += ranges.at(i).char_count - 1;

   m = snprintf(line, sizeof(line) - 1, "/*\n * LWS MCUFONT %s\n * blob size: %u, glyphs %u\n * \n",
		   datafile.GetFontInfo().name.c_str(), (unsigned int)filesize,
		   (unsigned int)cc);

   if (write(fd1, line, m) < 0)
	goto fail;

   for (size_t i = 0; i < ranges.size(); i++) {
	   m = snprintf(line, sizeof(line) - 1, " *   Unicode 0x%06x - 0x%06x\n",
			   ranges.at(i).first_char,
			   ranges.at(i).first_char + ranges.at(i).char_count - 1);

	   if (write(fd1, line, m) < 0)
		goto fail;
   }

   m = snprintf(line, sizeof(line) - 1, "*/\n\n");
   if (write(fd1, line, m) < 0)
	goto fail;

    do {
	uint8_t b[16];
	size_t n;
	ssize_t s;

	s = read(fd, b, sizeof(b));
	if (s <= 0)
		break;
	m = snprintf(line, sizeof(line) - 2, "/* %04X */  ", ao);
	for (n = 0; n < (size_t)s; n++) {
	    m += snprintf(line + m, sizeof(line) - 2 - m, "0x%02X, ", b[n]);
	    ao++;
	    if (ao == in32(&hdr[MCUFO_FOFS_FULLNAME]))
		    m += snprintf(line + m, sizeof(line) - 2 - m, "\n/* full name */\n");
	    if (ao == in32(&hdr[MCUFO_FOFS_NAME]))
		    m += snprintf(line + m, sizeof(line) - 2 - m, "\n/* short name */\n");
	    if (ao == in32(&hdr[MCUFO_FOFS_DICT_DATA]))
		    m += snprintf(line + m, sizeof(line) - 2 - m, "\n/* dictionary data */\n");
	    if (ao == in32(&hdr[MCUFO_FOFS_DICT_OFS]))
		    m += snprintf(line + m, sizeof(line) - 2 - m, "\n/* dictionary offset */\n");
	    if (ao == cri)
		    m += snprintf(line + m, sizeof(line) - 2 - m, "\n/* char range info */\n");
	    if (ao == in32(&hdr[MCUFO_FOFS_CHAR_RANGE_TABLES]))
		    m += snprintf(line + m, sizeof(line) - 2 - m, "\n/* char range ofs tables */\n");
	}

	if (write(fd1, line, m) < 0)
		goto fail;
	line[0] = '\n';
	if (write(fd1, line, 1) < 0)
		goto fail;
    } while (1);
    close(fd1);
    close(fd);



    return;
    
fail:
	close(fd);
	fprintf(stderr, "ERROR writing file\n");
}

}}

