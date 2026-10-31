// Function for importing any font supported by libfreetype.

#pragma once
#include "datafile.hh"
#include <set>
#include <string>

namespace mcufont {

// The font is named with its size, unless sized_name is false: the pages of
// a face are all named the same whatever their size, see FreetypeInfo().
std::unique_ptr<DataFile> LoadFreetype(std::istream &file, int size, bool bw,
                                       bool sized_name = true);

// What a face is at any size, without rendering any of it: its name, its
// height and units per em, from which its line height at a size is
// (height * size + units_per_em / 2) / units_per_em, and which 256-codepoint
// pages its charmap has glyphs in.
struct freetype_info_t
{
    std::string name;
    int height;
    int units_per_em;
    std::set<uint32_t> pages;
};

bool FreetypeInfo(std::istream &file, freetype_info_t &info);

}
