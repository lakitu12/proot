/* -*- c++-set-style: "K&R"; c-basic-offset: 8 -*- */
#include <cstddef>
#include <cstdint>

extern const char _binary_loader_exe_start[];
extern const char _binary_loader_exe_end[];

extern "C" {
    const char _binary_loader_exe_start[] = {
#include "loader.inc"
    };

    const char _binary_loader_exe_end[] = {};
    const int offset_to_pokedata_workaround = 0;
}
