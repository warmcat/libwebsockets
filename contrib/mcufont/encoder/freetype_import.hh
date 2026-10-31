// Function for importing any font supported by libfreetype.

#pragma once
#include "datafile.hh"
#include <set>
#include <string>

namespace mcufont {

std::unique_ptr<DataFile> LoadFreetype(std::istream &file, int size, bool bw);

// What a face is, without rendering any of it: its name and line height at
// size, and which 256-codepoint pages its charmap has glyphs in.
struct freetype_info_t
{
    std::string name;
    int line_height;
    std::set<uint32_t> pages;
};

bool FreetypeInfo(std::istream &file, int size, freetype_info_t &info);

}
