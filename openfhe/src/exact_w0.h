#pragma once

#include "composition_fixture.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace exact_w0 {
constexpr uint32_t prime = 65537;
constexpr unsigned points = 32;
using Jet = std::vector<uint16_t>;
using Powers = std::vector<Jet>;
inline void require(bool b, const char* message) {
    if (!b) throw std::runtime_error(message);
}
inline uint32_t powmod(uint32_t a, uint32_t n) {
    uint64_t r = 1;
    for (; n; n >>= 1, a = uint64_t(a) * a % prime)
        if (n & 1) r = r * a % prime;
    return uint32_t(r);
}
inline uint32_t canonical(int64_t x) {
    x %= prime;
    return uint32_t(x < 0 ? x + prime : x);
}
inline Jet product(const Jet& a, const Jet& b) {
    require(a.size() == b.size(), "series lengths differ");
    Jet out(a.size());
    for (unsigned i = 0; i < a.size(); ++i) if (a[i])
        for (unsigned j = 0; j + i < a.size(); ++j) if (b[j])
            out[i+j] ^= fixture::multiply(a[i], b[j]);
    return out;
}
inline Jet horner(const Jet& f, const Jet& g) {
    require(f.size() == g.size() && g[0] == 0, "invalid composition input");
    Jet out(f.size());
    for (unsigned i = unsigned(f.size()); i > 0; --i) {
        out = product(out, g);
        out[0] ^= f[i-1];
    }
    return out;
}
inline Powers powers(const Jet& g) {
    require(g[0] == 0, "nonzero constant in g");
    Powers out(g.size(), Jet(g.size()));
    out[0][0] = 1;
    for (unsigned i = 1; i < g.size(); ++i) out[i] = product(out[i-1], g);
    return out;
}
struct Inputs { std::vector<Jet> f, g; uint64_t full_fixture_checksum{}; };
inline Inputs inputs(unsigned jobs, unsigned length) {
    require(jobs > 0 && jobs <= fixture::JOBS, "jobs outside fixture");
    require(length >= 2 && length <= fixture::L && !(length & (length-1)), "invalid power-of-two length");
    const auto source = fixture::inputs();
    Inputs in;
    in.full_fixture_checksum = fixture::checksum(source);
    for (unsigned j = 0; j < jobs; ++j) {
        in.f.emplace_back(source.f[j].begin(), source.f[j].begin() + length);
        in.g.emplace_back(source.g[j].begin(), source.g[j].begin() + length);
    }
    return in;
}

// Exact prime-field evaluation of binary polynomial representatives. The table
// is public and independent of either owner's inputs; its construction is charged.
struct Codec {
    uint32_t root{};
    std::array<uint32_t, points> inverse_roots{};
    std::vector<std::array<uint32_t, points>> values;
    Codec() : root(powmod(3, (prime-1)/points)), values(65536) {
        require(powmod(root, points) == 1 && powmod(root, points/2) == prime-1,
                "root does not have order32");
        const auto inverse = powmod(root, prime-2);
        for (unsigned t = 0; t < points; ++t) {
            inverse_roots[t] = powmod(inverse, t);
            std::array<uint32_t, 16> basis{};
            basis[0] = 1;
            const auto x = powmod(root, t);
            for (unsigned bit = 1; bit < 16; ++bit) basis[bit] = uint64_t(basis[bit-1]) * x % prime;
            for (unsigned a = 1; a < 65536; ++a) {
                const unsigned bit = unsigned(__builtin_ctz(a));
                values[a][t] = (values[a & (a-1)][t] + basis[bit]) % prime;
            }
        }
    }
    uint16_t recover(std::array<uint32_t, points> data, unsigned bound) const {
        // Inverse radix-two NTT. No coefficient wraps modulo65537 because the
        // integer convolution coefficient bound is at most16*length <=4096.
        for (unsigned i = 1, j = 0; i < points; ++i) {
            unsigned b = points >> 1;
            for (; j & b; b >>= 1) j ^= b;
            j ^= b;
            if (i < j) std::swap(data[i], data[j]);
        }
        for (unsigned width = 2; width <= points; width <<= 1) {
            const uint32_t step = inverse_roots[points/width];
            for (unsigned start = 0; start < points; start += width) {
                uint64_t w = 1;
                for (unsigned j = 0; j < width/2; ++j) {
                    const auto u = data[start+j];
                    const auto v = uint32_t(w * data[start+j+width/2] % prime);
                    data[start+j] = (u + v) % prime;
                    data[start+j+width/2] = (u + prime - v) % prime;
                    w = w * step % prime;
                }
            }
        }
        uint32_t binary = 0;
        constexpr uint32_t inv32 = 63489; //32*63489 ==1 mod65537.
        for (unsigned k = 0; k < points; ++k) {
            data[k] = uint64_t(data[k]) * inv32 % prime;
            require(data[k] <= bound, "integer-lift coefficient exceeds declared bound");
            if (k == 31) require(data[k] == 0, "unexpected degree31 coefficient");
            if (data[k] & 1) binary ^= uint32_t(1) << k;
        }
        for (int k = 30; k >= 16; --k)
            if (binary & (uint32_t(1) << k)) binary ^= uint32_t(0x1100b) << (k-16);
        return uint16_t(binary);
    }
};

// OpenFHE power-of-two packed encoding has two cyclic rows. Interleaving jobs
// inside each coefficient makes every giant rotation stay within its own job.
struct Layout {
    unsigned n, length, jobs_per_half, capacity;
    Layout(unsigned dimension, unsigned l) : n(dimension), length(l),
        jobs_per_half(n / (2*points*length)), capacity(2*jobs_per_half) {
        require(jobs_per_half && n == 2*points*length*jobs_per_half,
                "ring cannot hold a complete coefficient cycle per packed row");
    }
    unsigned slot(unsigned job, unsigned coefficient, unsigned point) const {
        return (job / jobs_per_half) * (n/2) + point + points *
               ((job % jobs_per_half) + jobs_per_half*coefficient);
    }
    int32_t rotation(unsigned coefficient_shift) const {
        return int32_t(points*jobs_per_half*coefficient_shift);
    }
};
} // namespace exact_w0
