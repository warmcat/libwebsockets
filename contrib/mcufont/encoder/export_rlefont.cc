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
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#define RLEFONT_FORMAT_VERSION		6
#define RELFONT_HDR_LEN			64
#define RELFONT_RANGE_HDR_LEN		16

#define MAX_RANGES			32

/*
 * The glyph height is cut into at most this many bands for the kerning
 * profiles, a row each for all but the biggest faces
 */
#define KERN_MAX_BANDS			64
#define KERN_NO_INK			0xff
#define KERN_ESCAPE			0x88

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

	MCUFO_KERN_BANDS		= 0x3e,
	MCUFO_KERN_GAP			= 0x3f
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

/*
 * The glyph's ink, band by band: the glyph height is cut into horizontal
 * bands, normally a row each, and for each band we keep the leftmost and
 * rightmost columns with any ink in any of its rows.  The decoder kerns a
 * pair of glyphs from these alone, so layout can place glyphs without
 * decoding them.  A band with no ink between ones that have some, like the
 * gap in an 'i', takes the extent of the band above: like taking the
 * extremes of the rows in a band, that can only ever leave glyphs a little
 * further apart, never overlapping.
 */

struct kern_profile_t
{
    int first, last; /* the inked bands, or first > last for no ink */
    uint8_t l[KERN_MAX_BANDS], r[KERN_MAX_BANDS];
};

static int kern_bands(const DataFile &datafile)
{
    return std::min(KERN_MAX_BANDS, datafile.GetFontInfo().max_height);
}

static kern_profile_t kern_profile(const DataFile &datafile, int glyph_index)
{
    const DataFile::fontinfo_t &fi = datafile.GetFontInfo();
    int bands = kern_bands(datafile);
    bool ink[KERN_MAX_BANDS] = { false };
    kern_profile_t p;

    p.first = bands;
    p.last = -1;
    for (int b = 0; b < KERN_MAX_BANDS; b++) {
        p.l[b] = 0;
        p.r[b] = 0;
    }

    if (glyph_index < 0)
        return p;

    const DataFile::pixels_t &px = datafile.GetGlyphEntry(glyph_index).data;

    for (int y = 0; y < fi.max_height; y++) {
        int b = y * bands / fi.max_height;

        for (int x = 0; x < fi.max_width; x++) {
            if (!px.at((size_t)(y * fi.max_width + x)))
                continue;
            if (!ink[b] || x < p.l[b])
                p.l[b] = (uint8_t)x;
            if (!ink[b] || x > p.r[b])
                p.r[b] = (uint8_t)x;
            ink[b] = true;
            p.first = std::min(p.first, b);
            p.last = std::max(p.last, b);
        }
    }

    for (int b = p.first + 1; b <= p.last; b++)
        if (!ink[b]) {
            p.l[b] = p.l[b - 1];
            p.r[b] = p.r[b - 1];
        }

    return p;
}

/*
 * The profile as it goes in the glyph string, after the width: the first and
 * last inked bands and the first band's edges, then for each band after, the
 * change in its edges as two signed nibbles, or if either is too big for
 * that, KERN_ESCAPE and the two edges.  Just KERN_NO_INK if the glyph has no
 * ink at all.
 */

static void kern_profile_append(const kern_profile_t &p,
                                std::vector<unsigned> &data)
{
    if (p.first > p.last) {
        data.push_back(KERN_NO_INK);
        return;
    }

    data.push_back((unsigned)p.first);
    data.push_back((unsigned)p.last);
    data.push_back(p.l[p.first]);
    data.push_back(p.r[p.first]);

    for (int b = p.first + 1; b <= p.last; b++) {
        int dl = p.l[b] - p.l[b - 1], dr = p.r[b] - p.r[b - 1];

        if (dl < -7 || dl > 7 || dr < -7 || dr > 7) {
            data.push_back(KERN_ESCAPE);
            data.push_back(p.l[b]);
            data.push_back(p.r[b]);
        } else
            data.push_back((unsigned)(((dl & 0xf) << 4) | (dr & 0xf)));
    }
}

static size_t kern_profile_size(const kern_profile_t &p)
{
    std::vector<unsigned> data;

    kern_profile_append(p, data);

    return data.size();
}

/*
 * The closest the ink of glyph b comes to the ink of glyph a before it, in
 * clear columns: each band of a against the bands of b alongside it and
 * either side, so glyphs that kern under one another don't touch at the
 * corners either.  INT_MAX if they have no bands alongside each other.
 */

static int kern_min_gap(const kern_profile_t &a, int a_width,
                        const kern_profile_t &b)
{
    int gap = INT_MAX;

    for (int n = a.first; n <= a.last; n++)
        for (int m = std::max(n - 1, b.first);
             m <= std::min(n + 1, b.last); m++)
            gap = std::min(gap, a_width + b.l[m] - a.r[n] - 1);

    return gap;
}

/*
 * The gap the decoder closes pairs up to: the font's own spacing, taken as
 * the median of the closest approach between all the pairs of letters.
 * Pairs that sit further apart than that are moved in towards it.  Small
 * faces are often set so tight that the median has no clear column, but
 * kerning never brings ink together: pairs the face has touching stay so,
 * and it only closes others up to one clear column.
 */

int kern_target_gap(const DataFile &datafile)
{
    std::vector<int> letters, gaps;

    for (size_t i = 0; i < datafile.GetGlyphCount(); i++)
        for (int c : datafile.GetGlyphEntry(i).chars)
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
                letters.push_back((int)i);

    for (int a : letters) {
        kern_profile_t pa = kern_profile(datafile, a);

        for (int b : letters) {
            int g = kern_min_gap(pa, datafile.GetGlyphEntry(a).width,
                                 kern_profile(datafile, b));

            if (g != INT_MAX)
                gaps.push_back(g);
        }
    }

    if (gaps.empty())
        return 1;

    std::sort(gaps.begin(), gaps.end());

    return std::max(1, std::min(255, gaps[gaps.size() / 2]));
}

bool write_source(std::ostream &out, std::string _name, const DataFile &datafile,
                  const export_opts_t &opts)
{
    std::string name = filename_to_identifier(opts.ident.empty() ? _name :
                                                                   opts.ident),
                n1 = _name;
    std::unique_ptr<encoded_font_t> encoded = encode_font(datafile, false);
    std::vector<char_range_t> ranges;
    uint32_t filesize, cri;
    char line[200];
    size_t m, cc, ao = 0;

    auto get_glyph_size = [&encoded, &datafile](size_t i)
    {
        // +1 byte for glyph width, then the kerning profile
        return encoded->glyphs[i].size() + 1 +
               kern_profile_size(kern_profile(datafile, (int)i));
    };

    std::cout << "Writing " + n1 + '\n';
    fd = open(n1.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
	    fprintf(stderr, "Failed to open %s\n", n1.c_str());
	    return false;
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
	      datafile.GetFontInfo().name.length() + 1) < 0)
	    goto fail;
    out32(&hdr[MCUFO_FOFS_NAME], (uint32_t)lseek(fd, 0, SEEK_END));
    if (write(fd, name.c_str(), name.length() + 1) < 0)
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
                kern_profile_append(kern_profile(datafile, glyph_index), data);
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
    hdr[MCUFO_KERN_BANDS] = (uint8_t)kern_bands(datafile);
    hdr[MCUFO_KERN_GAP] = (uint8_t)(opts.kern_gap ? opts.kern_gap :
                                            kern_target_gap(datafile));

    filesize = (uint32_t)lseek(fd, 0, SEEK_END);

    if (lseek(fd, 0, SEEK_SET) < 0)
	    goto fail;
    if (write(fd, hdr, RELFONT_HDR_LEN) < 0)
	    goto fail;

    if (!opts.c_header) {
	    close(fd);
	    return true;
    }

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

    return true;

fail:
	close(fd);
	fprintf(stderr, "ERROR writing file\n");

	return false;
}

}}

