#include "composition_fixture.h"
#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: export_fixture NEW_OUTPUT.bin\n";
        return 2;
    }
    std::ifstream existing(argv[1], std::ios::binary);
    if (existing.good()) {
        std::cerr << "output already exists\n";
        return 2;
    }
    const auto in = fixture::inputs();
    std::ofstream out(argv[1], std::ios::binary);
    if (!out) return 1;
    for (unsigned j = 0; j < fixture::JOBS; ++j)
        for (const fixture::Jet* jet : {&in.f[j], &in.g[j]})
            for (uint16_t value : *jet) {
                out.put(static_cast<char>(value & 255));
                out.put(static_cast<char>(value >> 8));
            }
    out.close();
    if (!out) return 1;
    std::cout << "{\"jobs\":16,\"length\":256,\"input_symbols\":8192,"
              << "\"fixture_fnv1a64\":\"" << fixture::checksum(in) << "\"}\n";
}
