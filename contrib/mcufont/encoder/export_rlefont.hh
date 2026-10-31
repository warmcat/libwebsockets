// Write out the encoded data in C source code files for the mf_rlefont format.

#pragma once

#include "datafile.hh"
#include "encode_rlefont.hh"
#include <iostream>

namespace mcufont {
namespace rlefont {

// How write_source() writes the face.
struct export_opts_t {
    // The gap kerning closes pairs up to, or 0 to work it out from the
    // letters in the datafile.  A page of a face may have no letters, so it
    // is given the whole face's.
    int kern_gap = 0;
    // Also write <name>.h, the face as a C array to build into flash.
    bool c_header = true;
    // The face's short name, if not made from the file name.
    std::string ident;
};

// The gap between letter pairs the face's kerning closes up to.
int kern_target_gap(const DataFile &datafile);

// Write the face to the file name.  Returns false if it couldn't.
bool write_source(std::ostream &out, std::string name, const DataFile &datafile,
                  const export_opts_t &opts = export_opts_t());

} }

