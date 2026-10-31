#include "datafile.hh"
#include "importtools.hh"
#include "bdf_import.hh"
#include "freetype_import.hh"
#include "export_rlefont.hh"
#include "encode_rlefont.hh"
#include "optimize_rlefont.hh"
#include "export_bwfont.hh"
#include <vector>
#include <string>
#include <set>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <ctime>
#include <map>
#include "ccfixes.hh"
#include "gb2312_in_ucs2.h"

using namespace mcufont;

static std::string strip_extension(std::string filename)
{
    size_t pos = filename.find_last_of('.');
    
    if (pos == std::string::npos)
    {
        return filename;
    }
    else
    {
        return filename.substr(0, pos);
    }
}

static std::unique_ptr<DataFile> load_dat(std::string src)
{
    std::ifstream infile(src);
    
    if (!infile.good())
    {
        std::cerr << "Could not open " << src << std::endl;
        return nullptr;
    }
    
    std::unique_ptr<DataFile> f = DataFile::Load(infile);
    if (!f)
    {
        std::cerr << "Invalid format for .dat file: " << src << std::endl;
        return nullptr;
    }
    
    return f;
}

static bool save_dat(std::string dest, DataFile *f)
{
    std::ofstream outfile(dest);
    
    if (!outfile.good())
    {
        std::cerr << "Could not open " << dest << std::endl;
        return false;
    }
    
    f->Save(outfile);
    
    if (!outfile.good())
    {
        std::cerr << "Could not write to " << dest << std::endl;
        return false;
    }
    
    return true;
}

enum status_t
{
    STATUS_OK = 0, // All good
    STATUS_INVALID = 1, // Invalid command or args
    STATUS_ERROR = 2 // Error when executing command
};

static status_t cmd_import_ttf(const std::vector<std::string> &args)
{
    if (args.size() != 3 && args.size() != 4)
        return STATUS_INVALID;
    
    std::string src = args.at(1);
    int size = std::stoi(args.at(2));
    bool bw = (args.size() == 4 && args.at(3) == "bw");
    std::string dest = strip_extension(src) + std::to_string(size) + (bw ? "bw" : "") + ".dat";
    std::ifstream infile(src);
    
    if (!infile.good())
    {
        std::cerr << "Could not open " << src << std::endl;
        return STATUS_ERROR;
    }
    
    std::cout << "Importing " << src << " to " << dest << std::endl;
    
    std::unique_ptr<DataFile> f = LoadFreetype(infile, size, bw);
    
    mcufont::rlefont::init_dictionary(*f);
    
    if (!save_dat(dest, f.get()))
        return STATUS_ERROR;
    
    std::cout << "Done: " << f->GetGlyphCount() << " unique glyphs." << std::endl;
    return STATUS_OK;
}

static status_t cmd_import_bdf(const std::vector<std::string> &args)
{
    if (args.size() != 2)
        return STATUS_INVALID;
    
    std::string src = args.at(1);
    std::string dest = strip_extension(args.at(1)) + ".dat";
    std::ifstream infile(src);
    
    if (!infile.good())
    {
        std::cerr << "Could not open " << src << std::endl;
        return STATUS_ERROR;
    }
    
    std::cout << "Importing " << src << " to " << dest << std::endl;
    
    std::unique_ptr<DataFile> f = LoadBDF(infile);
    
    mcufont::rlefont::init_dictionary(*f);
    
    if (!save_dat(dest, f.get()))
        return STATUS_ERROR;
    
    std::cout << "Done: " << f->GetGlyphCount() << " unique glyphs." << std::endl;
    return STATUS_OK;
}

static status_t cmd_filter(const std::vector<std::string> &args)
{
    if (args.size() < 3)
        return STATUS_INVALID;
    
    std::set<int> allowed;
    
    // Parse arguments
    for (size_t i = 2; i < args.size(); i++)
    {
        std::string s = args.at(i);
        size_t pos = s.find('-');
        if (pos == std::string::npos)
        {
            if(s == "gb2312") {
                allowed.insert(
                    &gb2312_in_ucs2_codetable[0],
                    &gb2312_in_ucs2_codetable[sizeof(gb2312_in_ucs2_codetable)/sizeof(gb2312_in_ucs2_codetable[0])]);
            } else {
                // Single char
                allowed.insert(std::stoi(s, nullptr, 0));
            }
        }
        else
        {
            // Range
            int start = std::stoi(s.substr(0, pos), nullptr, 0);
            int end = std::stoi(s.substr(pos + 1), nullptr, 0);
            
            for (int j = start; j <= end; j++)
            {
                allowed.insert(j);
            }
        }
    }
    
    std::string src = args.at(1);
    std::unique_ptr<DataFile> f = load_dat(src);
    if (!f)
        return STATUS_ERROR;
    
    std::cout << "Font originally had " << f->GetGlyphCount() << " glyphs." << std::endl;
    
    // Filter the glyphs
    std::vector<DataFile::glyphentry_t> newglyphs;
    for (size_t i = 0; i < f->GetGlyphCount(); i++)
    {
        DataFile::glyphentry_t g = f->GetGlyphEntry(i);
        
        for (size_t j = 0; j < g.chars.size(); j++)
        {
            if (!allowed.count(g.chars.at(j)))
            {
                g.chars.erase(g.chars.begin() + j);
                j--;
            }
        }
        
        if (g.chars.size())
        {
            newglyphs.push_back(g);
        }
    }
    
    DataFile::fontinfo_t fontinfo = f->GetFontInfo();
    crop_glyphs(newglyphs, fontinfo);
    detect_flags(newglyphs, fontinfo);
    
    f.reset(new DataFile(f->GetDictionary(), newglyphs, fontinfo));
    std::cout << "After filtering, " << f->GetGlyphCount() << " glyphs remain." << std::endl;
    
    if (!save_dat(src, f.get()))
        return STATUS_ERROR;
    
    return STATUS_OK;
}

static status_t cmd_show_glyph(const std::vector<std::string> &args)
{
    if (args.size() != 3)
        return STATUS_INVALID;
    
    std::string src = args.at(1);
    std::unique_ptr<DataFile> f = load_dat(src);
    
    if (!f)
        return STATUS_ERROR;
    
    size_t index = 0;
    if (args.at(2) == "largest")
    {
        std::unique_ptr<mcufont::rlefont::encoded_font_t> e =
            mcufont::rlefont::encode_font(*f, false);
        size_t maxlen = 0;
        size_t i = 0;
        for (mcufont::rlefont::encoded_font_t::refstring_t g : e->glyphs)
        {
            if (g.size() > maxlen)
            {
                maxlen = g.size();
                index = i;
            }
            i++;
        }
        
        std::cout << "Index " << index << ", length " << maxlen << std::endl;
    }
    else
    {
        index = strtol(args.at(2).c_str(), nullptr, 0);
    }
    
    if (index >= f->GetGlyphCount())
    {
        std::cerr << "No such glyph " << index << std::endl;
        return STATUS_ERROR;
    }
    
    std::cout << "Width: " << f->GetGlyphEntry(index).width << std::endl;
    std::cout << "Chars: ";
    for (int c: f->GetGlyphEntry(index).chars) std::cout << c << " ";
    std::cout << std::endl;
    
    std::cout << f->GlyphToText(index);
    return STATUS_OK;
}

static status_t cmd_rlefont_export(const std::vector<std::string> &args)
{
    if (args.size() != 2 && args.size() != 3)
        return STATUS_INVALID;
    
    std::string src = args.at(1);
    std::string dst = (args.size() == 2) ? strip_extension(src) + ".mcufont" : args.at(2);
    std::unique_ptr<DataFile> f = load_dat(src);
    
    if (!f)
        return STATUS_ERROR;
    
    {
        std::ofstream source(dst);
        mcufont::rlefont::write_source(source, dst, *f);
        std::cout << "Wrote " << dst << std::endl;
    }
    
    return STATUS_OK;
}

static status_t cmd_rlefont_size(const std::vector<std::string> &args)
{
    if (args.size() != 2)
        return STATUS_INVALID;
    
    std::string src = args.at(1);
    std::unique_ptr<DataFile> f = load_dat(src);
    
    if (!f)
        return STATUS_ERROR;
    
    size_t size = mcufont::rlefont::get_encoded_size(*f);
    
    std::cout << "Glyph count:       " << f->GetGlyphCount() << std::endl;
    std::cout << "Glyph bbox:        " << f->GetFontInfo().max_width << "x"
        << f->GetFontInfo().max_height << " pixels" << std::endl;
    std::cout << "Uncompressed size: " << f->GetGlyphCount() *
        f->GetFontInfo().max_width * f->GetFontInfo().max_height / 2
        << " bytes" << std::endl;
    std::cout << "Compressed size:   " << size << " bytes" << std::endl;
    std::cout << "Bytes per glyph:   " << size / f->GetGlyphCount() << std::endl;
    return STATUS_OK;
}

static status_t cmd_rlefont_optimize(const std::vector<std::string> &args)
{
    if (args.size() != 2 && args.size() != 3)
        return STATUS_INVALID;
    
    std::string src = args.at(1);
    std::unique_ptr<DataFile> f = load_dat(src);
    
    if (!f)
        return STATUS_ERROR;
    
    size_t oldsize = mcufont::rlefont::get_encoded_size(*f);
    
    std::cout << "Original size is " << oldsize << " bytes" << std::endl;
    std::cout << "Press ctrl-C at any time to stop." << std::endl;
    std::cout << "Results are saved automatically after each iteration." << std::endl;
    
    int limit = 100;
    if (args.size() == 3)
    {
        limit = std::stoi(args.at(2));
    }
    
    if (limit > 0)
        std::cout << "Limit is " << limit << " iterations" << std::endl;
    
    int i = 0;
    time_t oldtime = time(NULL);
    while (!limit || i < limit)
    {
        mcufont::rlefont::optimize(*f);

        size_t newsize = mcufont::rlefont::get_encoded_size(*f);
        time_t newtime = time(NULL);
        
        int bytes_per_min = (oldsize - newsize) * 60 / (newtime - oldtime + 1);
        
        i++;
        std::cout << "iteration " << i << ", size " << newsize
                  << " bytes, speed " << bytes_per_min << " B/min"
                  << std::endl;
        
        {
            if (!save_dat(src, f.get()))
                return STATUS_ERROR;
        }
    }
    
    return STATUS_OK;
}

static status_t cmd_rlefont_show_encoded(const std::vector<std::string> &args)
{
    if (args.size() != 2)
        return STATUS_INVALID;
    
    std::string src = args.at(1);
    std::unique_ptr<DataFile> f = load_dat(src);
    
    if (!f)
        return STATUS_ERROR;
    
    std::unique_ptr<mcufont::rlefont::encoded_font_t> e =
        mcufont::rlefont::encode_font(*f, false);

    int i = 0;
    for (mcufont::rlefont::encoded_font_t::rlestring_t d : e->rle_dictionary)
    {
        std::cout << "Dict RLE " << 24 + i++ << ": ";
        for (uint8_t v : d)
            std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)v << " ";
        std::cout << std::endl;
    }
    
    for (mcufont::rlefont::encoded_font_t::refstring_t d : e->ref_dictionary)
    {
        std::cout << "Dict Ref " << 24 + i++ << ": ";
        for (uint8_t v : d)
            std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)v << " ";
        std::cout << std::endl;
    }
    
    i = 0;
    for (mcufont::rlefont::encoded_font_t::refstring_t g : e->glyphs)
    {
        std::cout << "Glyph " << i++ << ": ";
        for (uint8_t v : g)
            std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)v << " ";
        std::cout << std::endl;
    }
    
    return STATUS_OK;
}

static status_t cmd_bwfont_export(const std::vector<std::string> &args)
{
    if (args.size() != 2 && args.size() != 3)
        return STATUS_INVALID;
    
    std::string src = args.at(1);
    std::string dst = (args.size() == 2) ? strip_extension(src) + ".c" : args.at(2);
    std::unique_ptr<DataFile> f = load_dat(src);
    
    if (!f)
        return STATUS_ERROR;
    
    if (!(f->GetFontInfo().flags & DataFile::FLAG_BW))
    {
        std::cout << "Warning: font is not black and white" << std::endl;
    }
    
    {
        std::ofstream source(dst);
        mcufont::bwfont::write_source(source, dst, *f);
        std::cout << "Wrote " << dst << std::endl;
    }
    
    return STATUS_OK;
}


/*
 * Commands for serving a face a page at a time.  A page is the glyphs for
 * 256 codepoints, page n being n * 256 to n * 256 + 255.  Each page is a
 * complete mcufont of its own, with the whole face's height, baseline, line
 * height and kerning gap, so text set from several pages lines up and kerns
 * as if they were one face.  See plugins/protocol_lws_mcufonts.
 */

static bool parse_int(const std::string &s, int base, int lo, int hi, int &v)
{
    try
    {
        size_t used;

        v = std::stoi(s, &used, base);
        return used == s.size() && v >= lo && v <= hi;
    }
    catch (std::exception &e)
    {
        return false;
    }
}

static std::string json_escape(const std::string &s)
{
    std::string r;
    char b[8];

    for (unsigned char c : s)
    {
        if (c == '"' || c == '\\')
        {
            r += '\\';
            r += (char)c;
        }
        else if (c < 0x20)
        {
            snprintf(b, sizeof(b), "\\u%04x", c);
            r += b;
        }
        else
            r += (char)c;
    }

    return r;
}

/*
 * What a face is at any size, on one line of stdout:
 *
 *   {"name":"Fira Sans Condensed Regular","height":1200,"units_per_em":1000,
 *    "pages":"0000-0005,0020-0022,..."}
 *
 * At a size, the face's line height is
 * (height * size + units_per_em / 2) / units_per_em, as rlefont_page gives
 * it.  pages are the pages its charmap has glyphs in, as ranges of hex page
 * numbers.  Nothing is rendered, so this is quick even for a big face.
 */

static status_t cmd_face_info(const std::vector<std::string> &args)
{
    freetype_info_t info;

    if (args.size() != 2)
        return STATUS_INVALID;

    std::ifstream infile(args.at(1));
    if (!infile.good())
    {
        std::cerr << "Could not open " << args.at(1) << std::endl;
        return STATUS_ERROR;
    }

    try
    {
        if (!FreetypeInfo(infile, info) || info.pages.empty())
        {
            std::cerr << "No usable glyphs in " << args.at(1) << std::endl;
            return STATUS_ERROR;
        }
    }
    catch (std::exception &e)
    {
        std::cerr << args.at(1) << ": " << e.what() << std::endl;
        return STATUS_ERROR;
    }

    std::string pages;
    char b[16];

    for (auto i = info.pages.begin(); i != info.pages.end(); )
    {
        uint32_t first = *i, last = first;

        while (++i != info.pages.end() && *i == last + 1)
            last = *i;

        if (first == last)
            snprintf(b, sizeof(b), "%04x", (unsigned int)first);
        else
            snprintf(b, sizeof(b), "%04x-%04x", (unsigned int)first,
                     (unsigned int)last);
        if (!pages.empty())
            pages += ',';
        pages += b;
    }

    std::cout << "{\"name\":\"" << json_escape(info.name) <<
                 "\",\"height\":" << info.height <<
                 ",\"units_per_em\":" << info.units_per_em <<
                 ",\"pages\":\"" << pages << "\"}" << std::endl;

    return STATUS_OK;
}

/*
 * Render, optimize and export one page of a face.  The face is imported
 * whole, so the height and baseline come from all of its glyphs, the same
 * for every page, and the kerning gap from its letters, which are mostly not
 * on the page; then only the page's glyphs are kept, cropped to the width
 * they need.  The page is named for the face without its size, since every
 * size of the face is listed once, by face_info's name.  Each iteration is a pass of the optimizer, as rlefont_optimize
 * does, so fewer trade size for time.
 */

static status_t cmd_rlefont_page(const std::vector<std::string> &args)
{
    mcufont::rlefont::export_opts_t opts;
    int size, page, iterations = 10;

    if (args.size() != 5 && args.size() != 6)
        return STATUS_INVALID;

    if (!parse_int(args.at(2), 10, 4, 255, size) ||
        !parse_int(args.at(3), 16, 0, 0x10ff, page) ||
        (args.size() == 6 &&
         !parse_int(args.at(5), 10, 0, 1000, iterations)))
        return STATUS_INVALID;

    std::ifstream infile(args.at(1));
    if (!infile.good())
    {
        std::cerr << "Could not open " << args.at(1) << std::endl;
        return STATUS_ERROR;
    }

    try
    {
        std::unique_ptr<DataFile> f = LoadFreetype(infile, size, false,
                                                   false);
        std::vector<DataFile::glyphentry_t> glyphs;

        opts.kern_gap = mcufont::rlefont::kern_target_gap(*f);
        opts.c_header = false;
        opts.ident = strip_extension(args.at(1).substr(
                        args.at(1).find_last_of('/') + 1)) +
                     std::to_string(size) + "-" + args.at(3);

        for (size_t i = 0; i < f->GetGlyphCount(); i++)
        {
            DataFile::glyphentry_t g = f->GetGlyphEntry(i);
            std::vector<int> chars;

            for (int c : g.chars)
                if (c >> 8 == page)
                    chars.push_back(c);

            if (chars.empty())
                continue;

            g.chars = chars;
            glyphs.push_back(g);
        }

        if (glyphs.empty())
        {
            std::cerr << "No glyphs on page " << args.at(3) << std::endl;
            return STATUS_ERROR;
        }

        DataFile::fontinfo_t fontinfo = f->GetFontInfo();
        fontinfo.flags &= ~(DataFile::FLAG_MONOSPACE | DataFile::FLAG_BW);
        crop_glyphs(glyphs, fontinfo, false);
        detect_flags(glyphs, fontinfo);

        DataFile pf(std::vector<DataFile::dictentry_t>(), glyphs, fontinfo);
        pf.SetSeed(1234);
        mcufont::rlefont::init_dictionary(pf);
        for (int i = 0; i < iterations; i++)
            mcufont::rlefont::optimize(pf);

        std::ofstream unused;
        if (!mcufont::rlefont::write_source(unused, args.at(4), pf, opts))
            return STATUS_ERROR;
    }
    catch (std::exception &e)
    {
        std::cerr << args.at(1) << ": " << e.what() << std::endl;
        return STATUS_ERROR;
    }

    return STATUS_OK;
}

static const char *usage_msg =
    "Usage: mcufont <command> [options] ...\n"
    "Commands for importing:\n"
    "   import_ttf <ttffile> <size> [bw]     Import a .ttf font into a data file.\n"
    "   import_bdf <bdffile>                 Import a .bdf font into a data file.\n"
    "\n"
    "Commands for inspecting and editing data files:\n"
    "   filter <datfile> <range> ...         Remove everything except specified characters.\n"
    "   show_glyph <datfile> <index>         Show the glyph at index.\n"
    "\n"
    "Commands specific to rlefont format:\n"
    "   rlefont_size <datfile>               Check the encoded size of the data file.\n"
    "   rlefont_optimize <datfile>           Perform an optimization pass on the data file.\n"
    "   rlefont_export <datfile> [outfile]   Export to .c source code.\n"
    "   rlefont_show_encoded <datfile>       Show the encoded data for debugging.\n"
    "\n"
    "Commands specific to bwfont format:\n"
    "   bwfont_export <datfile> [outfile]    Export to .c source code.\n"
    "\n"
    "Commands for serving a face a page of 256 codepoints at a time:\n"
    "   face_info <ttffile>                  Show the face's name, height and\n"
    "                                        units per em, and the pages it\n"
    "                                        has, as json.\n"
    "   rlefont_page <ttffile> <size> <page> <outfile> [iterations]\n"
    "                                        Make the .mcufont for one page\n"
    "                                        (hex), optimized for iterations\n"
    "                                        passes (default 10).\n"
    "";

typedef status_t (*cmd_t)(const std::vector<std::string> &args);
static const std::map<std::string, cmd_t> command_list {
    {"import_ttf",              cmd_import_ttf},
    {"import_bdf",              cmd_import_bdf},
    {"filter",                  cmd_filter},
    {"show_glyph",              cmd_show_glyph},
    {"rlefont_size",            cmd_rlefont_size},
    {"rlefont_optimize",        cmd_rlefont_optimize},
    {"rlefont_export",          cmd_rlefont_export},
    {"rlefont_show_encoded",    cmd_rlefont_show_encoded},
    {"bwfont_export",           cmd_bwfont_export},
    {"face_info",               cmd_face_info},
    {"rlefont_page",            cmd_rlefont_page},
};

int main(int argc, char **argv)
{
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++)
        args.push_back(argv[i]);
    
    status_t status = STATUS_INVALID;
    if (args.size() >= 1 && command_list.count(args.at(0)))
    {
        status = command_list.find(args.at(0))->second(args);
    }
    
    if (status == STATUS_INVALID)
    {
        std::cout << usage_msg << std::endl;
    }
    
    return status;
}
