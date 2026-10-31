// Utility functions for processing imported font files.

#pragma once
#include "datafile.hh"

namespace mcufont {

// Find and eliminate any duplicate glyphs by appending their char vectors.
void eliminate_duplicates(std::vector<DataFile::glyphentry_t> &glyphtable);

// Calculate the maximum bounding box of the glyphs and crop them to that.
// Adjust fontinfo accordingly.  Without vertical, only the width is cropped:
// the pages of a face share the face's height and baseline, so their rows
// line up, but each is only as wide as its own glyphs need.
void crop_glyphs(std::vector<DataFile::glyphentry_t> &glyphtable,
                 DataFile::fontinfo_t &fontinfo, bool vertical = true);

// Fill in the flags (BW, monospace) automatically.
void detect_flags(const std::vector<DataFile::glyphentry_t> &glyphtable,
                  DataFile::fontinfo_t &fontinfo);

}
