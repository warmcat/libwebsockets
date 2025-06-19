cmake_minimum_required(VERSION 3.10)
project(mfencoder)

find_package(Freetype REQUIRED)
find_package(Threads REQUIRED)
include_directories(${FREETYPE_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(lws-mcufont-encoder
        bdf_import.cc
        bdf_import.hh
        ccfixes.hh
        datafile.cc
        datafile.hh
        encode_rlefont.cc
        encode_rlefont.hh
        export_bwfont.cc
        export_bwfont.hh
        export_rlefont.cc
        export_rlefont.hh
        exporttools.cc
        exporttools.hh
        freetype_import.cc
        freetype_import.hh
        gb2312_in_ucs2.h
        importtools.cc
        importtools.hh
        main.cc
        optimize_rlefont.cc
        optimize_rlefont.hh)

target_link_libraries(lws-mcufont-encoder ${FREETYPE_LIBRARIES} Threads::Threads)
