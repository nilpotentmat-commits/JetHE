#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

#include "jet_circuit_ir.hpp"
#include "local_simd_codec.hpp"

namespace nilhe::jet::workloads {

inline constexpr std::size_t hermite255_degree = 255;
inline constexpr std::size_t hermite255_coefficient_count = 256;
inline constexpr std::size_t hermite255_points = 16;
inline constexpr std::size_t hermite255_jet_length = 16;
inline constexpr std::size_t hermite255_outputs =
    hermite255_points * hermite255_jet_length;

using DensePolynomial255 =
    std::array<std::uint16_t, hermite255_coefficient_count>;
using HermiteSymbol = std::array<std::uint16_t, hermite255_jet_length>;
using HermiteBatch = std::array<HermiteSymbol, hermite255_points>;
using ReducedSimdVector = std::array<std::uint16_t, hermite255_outputs>;

struct CarrierShape {
    std::size_t cyclotomic_index;
    std::size_t ring_dimension;
    std::size_t residue_degree;
    std::size_t field_slots;
    std::size_t completed_jet_capacity;
};

inline constexpr CarrierShape local_simd_carrier{
    8224, 4096, 16, 16, 16};
inline constexpr CarrierShape reduced_simd_carrier{
    4369, 4096, 16, 256, 16};

class BinaryField16 {
  public:
    explicit BinaryField16(std::uint32_t modulus) : modulus_(modulus) {
        if ((modulus_ >> 16) != 1u)
            throw std::invalid_argument(
                "BinaryField16: modulus must be monic of degree 16");
    }

    [[nodiscard]] std::uint32_t modulus() const noexcept { return modulus_; }

    [[nodiscard]] static std::uint16_t add(std::uint16_t left,
                                           std::uint16_t right) noexcept {
        return static_cast<std::uint16_t>(left ^ right);
    }

    [[nodiscard]] std::uint16_t multiply(std::uint16_t left,
                                         std::uint16_t right) const noexcept {
        std::uint32_t product = 0;
        for (std::size_t bit = 0; bit < 16; ++bit) {
            if (((right >> bit) & 1u) != 0)
                product ^= static_cast<std::uint32_t>(left) << bit;
        }
        for (int exponent = 30; exponent >= 16; --exponent) {
            if ((product & (std::uint32_t{1} << exponent)) != 0)
                product ^= modulus_ << (exponent - 16);
        }
        return static_cast<std::uint16_t>(product);
    }

    [[nodiscard]] std::uint16_t power(std::uint16_t base,
                                      std::uint32_t exponent) const noexcept {
        std::uint16_t result = 1;
        while (exponent != 0) {
            if ((exponent & 1u) != 0) result = multiply(result, base);
            base = multiply(base, base);
            exponent >>= 1;
        }
        return result;
    }

    [[nodiscard]] std::uint16_t inverse(std::uint16_t value) const {
        if (value == 0)
            throw std::invalid_argument("BinaryField16: inverse of zero");
        return power(value, 65534);
    }

    // Evaluate a binary polynomial represented by its coefficient bits.  This
    // accepts the degree-16 source modulus as a 17-bit word.
    [[nodiscard]] std::uint16_t evaluate_bits(std::uint32_t polynomial,
                                              std::uint16_t argument) const {
        int top = 31;
        while (top >= 0 &&
               (polynomial & (std::uint32_t{1} << top)) == 0) {
            --top;
        }
        std::uint16_t result = 0;
        for (int exponent = top; exponent >= 0; --exponent) {
            result = multiply(result, argument);
            if ((polynomial & (std::uint32_t{1} << exponent)) != 0)
                result ^= 1u;
        }
        return result;
    }

  private:
    std::uint32_t modulus_;
};

// A canonical comparison field is fixed by slot zero's irreducible factor.
// For every other Local-SIMD slot, source X is mapped to the first root of the
// source factor in that slot's field.  This makes one public F_(2^16)
// polynomial mean the same abstract polynomial in all sixteen local factors.
class LocalFieldIsomorphisms {
  public:
    explicit LocalFieldIsomorphisms(const LocalSimdCodec8224& codec)
        : source_modulus_(codec.factor(0)) {
        for (std::size_t slot = 0; slot < hermite255_points; ++slot) {
            target_moduli_[slot] = codec.factor(slot);
            const BinaryField16 target(target_moduli_[slot]);
            bool found = false;
            for (std::uint32_t candidate = 0; candidate < 65536; ++candidate) {
                if (target.evaluate_bits(
                        source_modulus_,
                        static_cast<std::uint16_t>(candidate)) == 0) {
                    roots_[slot] = static_cast<std::uint16_t>(candidate);
                    found = true;
                    break;
                }
            }
            if (!found)
                throw std::runtime_error(
                    "no source-field root in Local-SIMD coefficient field");
        }
    }

    [[nodiscard]] std::uint32_t source_modulus() const noexcept {
        return source_modulus_;
    }

    [[nodiscard]] std::uint32_t target_modulus(std::size_t slot) const {
        if (slot >= hermite255_points)
            throw std::out_of_range("LocalFieldIsomorphisms slot");
        return target_moduli_[slot];
    }

    [[nodiscard]] std::uint16_t map(std::size_t slot,
                                    std::uint16_t value) const {
        if (slot >= hermite255_points)
            throw std::out_of_range("LocalFieldIsomorphisms slot");
        const BinaryField16 target(target_moduli_[slot]);
        return target.evaluate_bits(value, roots_[slot]);
    }

  private:
    std::uint32_t source_modulus_ = 0;
    std::array<std::uint32_t, hermite255_points> target_moduli_{};
    std::array<std::uint16_t, hermite255_points> roots_{};
};

struct Hermite255Instance {
    DensePolynomial255 polynomial{};
    std::array<std::uint16_t, hermite255_points> points{};

    [[nodiscard]] static Hermite255Instance deterministic() {
        Hermite255Instance instance;
        std::uint64_t state = 0x4845524d495445ffULL;
        auto next_word = [&state]() {
            state += 0x9e3779b97f4a7c15ULL;
            std::uint64_t value = state;
            value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
            value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
            return value ^ (value >> 31);
        };
        for (std::uint16_t& coefficient : instance.polynomial) {
            coefficient = static_cast<std::uint16_t>(next_word());
            if (coefficient == 0) coefficient = 1;
        }
        for (std::size_t index = 0; index < hermite255_points; ++index) {
            std::uint16_t candidate = 0;
            bool unique = false;
            while (!unique) {
                candidate = static_cast<std::uint16_t>(next_word());
                unique = candidate != 0;
                for (std::size_t previous = 0; previous < index; ++previous)
                    unique = unique && instance.points[previous] != candidate;
            }
            instance.points[index] = candidate;
        }
        return instance;
    }
};

[[nodiscard]] inline bool binomial_is_odd(std::size_t n,
                                          std::size_t k) noexcept {
    return (k & ~n) == 0;
}

[[nodiscard]] inline HermiteBatch hasse_oracle(
    const Hermite255Instance& instance, const BinaryField16& field) {
    HermiteBatch result{};
    for (std::size_t point = 0; point < hermite255_points; ++point) {
        std::array<std::uint16_t, hermite255_coefficient_count> powers{};
        powers[0] = 1;
        for (std::size_t exponent = 1;
             exponent < hermite255_coefficient_count; ++exponent) {
            powers[exponent] = field.multiply(
                powers[exponent - 1], instance.points[point]);
        }
        for (std::size_t order = 0; order < hermite255_jet_length; ++order) {
            std::uint16_t value = 0;
            for (std::size_t exponent = order;
                 exponent < hermite255_coefficient_count; ++exponent) {
                if (binomial_is_odd(exponent, order)) {
                    value ^= field.multiply(
                        instance.polynomial[exponent],
                        powers[exponent - order]);
                }
            }
            result[point][order] = value;
        }
    }
    return result;
}

namespace detail {

using LocalBatch = LocalSimdCodec8224::Batch;

[[nodiscard]] inline LocalBatch local_one() {
    LocalBatch result{};
    for (auto& jet : result) jet[0] = 1;
    return result;
}

[[nodiscard]] inline LocalBatch local_add(const LocalBatch& left,
                                          const LocalBatch& right) {
    LocalBatch result{};
    for (std::size_t slot = 0; slot < hermite255_points; ++slot) {
        for (std::size_t order = 0; order < hermite255_jet_length; ++order)
            result[slot][order] = left[slot][order] ^ right[slot][order];
    }
    return result;
}

[[nodiscard]] inline LocalBatch local_scale(
    const LocalBatch& value,
    const std::array<std::uint16_t, hermite255_points>& scalars,
    const LocalFieldIsomorphisms& maps) {
    LocalBatch result{};
    for (std::size_t slot = 0; slot < hermite255_points; ++slot) {
        const BinaryField16 field(maps.target_modulus(slot));
        for (std::size_t order = 0; order < hermite255_jet_length; ++order) {
            result[slot][order] =
                field.multiply(value[slot][order], scalars[slot]);
        }
    }
    return result;
}

[[nodiscard]] inline LocalBatch evaluate_local_bsgs(
    const LocalSimdCodec8224& codec, const LocalFieldIsomorphisms& maps,
    const Hermite255Instance& instance) {
    LocalBatch argument{};
    for (std::size_t slot = 0; slot < hermite255_points; ++slot) {
        argument[slot][0] = maps.map(slot, instance.points[slot]);
        argument[slot][1] = 1;
    }

    std::array<LocalBatch, 17> powers{};
    powers[0] = local_one();
    powers[1] = argument;
    for (std::size_t exponent = 2; exponent <= 16; ++exponent) {
        powers[exponent] = codec.multiply_oracle(
            powers[exponent / 2], powers[(exponent + 1) / 2]);
    }

    std::array<LocalBatch, 16> blocks{};
    for (std::size_t block = 0; block < 16; ++block) {
        for (std::size_t degree = 0; degree < 16; ++degree) {
            std::array<std::uint16_t, hermite255_points> scalars{};
            const std::uint16_t coefficient =
                instance.polynomial[16 * block + degree];
            for (std::size_t slot = 0; slot < hermite255_points; ++slot)
                scalars[slot] = maps.map(slot, coefficient);
            blocks[block] = local_add(
                blocks[block], local_scale(powers[degree], scalars, maps));
        }
    }

    std::array<LocalBatch, 4> giant_powers{};
    giant_powers[0] = powers[16];
    for (std::size_t level = 1; level < 4; ++level) {
        giant_powers[level] = codec.multiply_oracle(
            giant_powers[level - 1], giant_powers[level - 1]);
    }
    std::size_t width = 16;
    for (std::size_t level = 0; level < 4; ++level) {
        const std::size_t next_width = width / 2;
        for (std::size_t index = 0; index < next_width; ++index) {
            blocks[index] = local_add(
                blocks[2 * index],
                codec.multiply_oracle(blocks[2 * index + 1],
                                      giant_powers[level]));
        }
        width = next_width;
    }
    return blocks[0];
}

[[nodiscard]] inline ReducedSimdVector reduced_add(
    const ReducedSimdVector& left, const ReducedSimdVector& right) {
    ReducedSimdVector result{};
    for (std::size_t lane = 0; lane < result.size(); ++lane)
        result[lane] = left[lane] ^ right[lane];
    return result;
}

[[nodiscard]] inline ReducedSimdVector reduced_multiply(
    const ReducedSimdVector& left, const ReducedSimdVector& right,
    const BinaryField16& field) {
    ReducedSimdVector result{};
    for (std::size_t lane = 0; lane < result.size(); ++lane)
        result[lane] = field.multiply(left[lane], right[lane]);
    return result;
}

[[nodiscard]] inline ReducedSimdVector evaluate_reduced_direct_hasse(
    const Hermite255Instance& instance, const BinaryField16& field) {
    ReducedSimdVector argument{};
    for (std::size_t point = 0; point < hermite255_points; ++point) {
        for (std::size_t order = 0; order < hermite255_jet_length; ++order)
            argument[point * hermite255_jet_length + order] =
                instance.points[point];
    }

    std::array<ReducedSimdVector, 17> powers{};
    powers[0].fill(1);
    powers[1] = argument;
    for (std::size_t exponent = 2; exponent <= 16; ++exponent) {
        powers[exponent] = reduced_multiply(
            powers[exponent / 2], powers[(exponent + 1) / 2], field);
    }

    std::array<ReducedSimdVector, 16> blocks{};
    for (std::size_t block = 0; block < 16; ++block) {
        for (std::size_t baby_degree = 0; baby_degree < 16; ++baby_degree) {
            const std::size_t x_exponent = 16 * block + baby_degree;
            ReducedSimdVector coefficient_vector{};
            for (std::size_t point = 0; point < hermite255_points; ++point) {
                for (std::size_t order = 0; order < hermite255_jet_length;
                     ++order) {
                    if (x_exponent + order < hermite255_coefficient_count &&
                        binomial_is_odd(x_exponent + order, order)) {
                        coefficient_vector[
                            point * hermite255_jet_length + order] =
                            instance.polynomial[x_exponent + order];
                    }
                }
            }
            blocks[block] = reduced_add(
                blocks[block],
                reduced_multiply(powers[baby_degree], coefficient_vector,
                                 field));
        }
    }

    std::array<ReducedSimdVector, 4> giant_powers{};
    giant_powers[0] = powers[16];
    for (std::size_t level = 1; level < 4; ++level) {
        giant_powers[level] = reduced_multiply(
            giant_powers[level - 1], giant_powers[level - 1], field);
    }
    std::size_t width = 16;
    for (std::size_t level = 0; level < 4; ++level) {
        const std::size_t next_width = width / 2;
        for (std::size_t index = 0; index < next_width; ++index) {
            blocks[index] = reduced_add(
                blocks[2 * index],
                reduced_multiply(blocks[2 * index + 1],
                                 giant_powers[level], field));
        }
        width = next_width;
    }
    return blocks[0];
}

[[nodiscard]] inline std::uint16_t evaluate_scalar_bsgs(
    const DensePolynomial255& polynomial, std::uint16_t argument,
    const BinaryField16& field) {
    std::array<std::uint16_t, 17> powers{};
    powers[0] = 1;
    powers[1] = argument;
    for (std::size_t exponent = 2; exponent <= 16; ++exponent) {
        powers[exponent] = field.multiply(
            powers[exponent / 2], powers[(exponent + 1) / 2]);
    }
    std::array<std::uint16_t, 16> blocks{};
    for (std::size_t block = 0; block < 16; ++block) {
        for (std::size_t degree = 0; degree < 16; ++degree) {
            blocks[block] ^= field.multiply(
                polynomial[16 * block + degree], powers[degree]);
        }
    }
    std::array<std::uint16_t, 4> giant_powers{};
    giant_powers[0] = powers[16];
    for (std::size_t level = 1; level < 4; ++level) {
        giant_powers[level] = field.multiply(
            giant_powers[level - 1], giant_powers[level - 1]);
    }
    std::size_t width = 16;
    for (std::size_t level = 0; level < 4; ++level) {
        const std::size_t next_width = width / 2;
        for (std::size_t index = 0; index < next_width; ++index) {
            blocks[index] = static_cast<std::uint16_t>(
                blocks[2 * index] ^
                field.multiply(blocks[2 * index + 1],
                               giant_powers[level]));
        }
        width = next_width;
    }
    return blocks[0];
}

[[nodiscard]] inline DensePolynomial255 interpolate_newton(
    const std::array<std::uint16_t, hermite255_coefficient_count>& nodes,
    const std::array<std::uint16_t, hermite255_coefficient_count>& values,
    const std::vector<std::uint16_t>& inverse_denominators,
    const BinaryField16& field) {
    if (inverse_denominators.size() !=
        hermite255_coefficient_count * hermite255_coefficient_count) {
        throw std::invalid_argument(
            "Newton inverse-denominator table has wrong shape");
    }
    auto divided = values;
    for (std::size_t order = 1; order < hermite255_coefficient_count; ++order) {
        for (int index = static_cast<int>(hermite255_degree);
             index >= static_cast<int>(order); --index) {
            const std::size_t upper = static_cast<std::size_t>(index);
            divided[upper] = field.multiply(
                divided[upper] ^ divided[upper - 1],
                inverse_denominators[
                    order * hermite255_coefficient_count + upper]);
        }
    }

    std::vector<std::uint16_t> monomial{divided[hermite255_degree]};
    for (int index = static_cast<int>(hermite255_degree) - 1;
         index >= 0; --index) {
        std::vector<std::uint16_t> next(monomial.size() + 1, 0);
        for (std::size_t degree = 0; degree < monomial.size(); ++degree) {
            next[degree] ^= field.multiply(
                monomial[degree], nodes[static_cast<std::size_t>(index)]);
            next[degree + 1] ^= monomial[degree];
        }
        next[0] ^= divided[static_cast<std::size_t>(index)];
        monomial = std::move(next);
    }
    if (monomial.size() != hermite255_coefficient_count)
        throw std::logic_error("Newton interpolation degree invariant failed");
    DensePolynomial255 result{};
    std::copy(monomial.begin(), monomial.end(), result.begin());
    return result;
}

[[nodiscard]] inline DensePolynomial255 shifted_coefficients(
    const DensePolynomial255& polynomial, std::uint16_t point,
    const BinaryField16& field) {
    DensePolynomial255 result{};
    std::array<std::uint16_t, hermite255_coefficient_count> powers{};
    powers[0] = 1;
    for (std::size_t exponent = 1;
         exponent < hermite255_coefficient_count; ++exponent)
        powers[exponent] = field.multiply(powers[exponent - 1], point);
    for (std::size_t order = 0; order < hermite255_coefficient_count; ++order) {
        for (std::size_t exponent = order;
             exponent < hermite255_coefficient_count; ++exponent) {
            if (binomial_is_odd(exponent, order)) {
                result[order] ^= field.multiply(
                    polynomial[exponent], powers[exponent - order]);
            }
        }
    }
    return result;
}

struct InterpolationResult {
    HermiteBatch symbols{};
    bool full_shift_polynomials_match = true;
};

[[nodiscard]] inline InterpolationResult evaluate_interpolation_baseline(
    const Hermite255Instance& instance, const BinaryField16& field) {
    InterpolationResult result;
    std::array<std::uint16_t, hermite255_coefficient_count> nodes{};
    for (std::size_t index = 0; index < nodes.size(); ++index)
        nodes[index] = static_cast<std::uint16_t>(index);
    std::vector<std::uint16_t> inverse_denominators(
        hermite255_coefficient_count * hermite255_coefficient_count, 0);
    for (std::size_t order = 1; order < hermite255_coefficient_count; ++order) {
        for (std::size_t upper = order;
             upper < hermite255_coefficient_count; ++upper) {
            inverse_denominators[
                order * hermite255_coefficient_count + upper] =
                field.inverse(nodes[upper] ^ nodes[upper - order]);
        }
    }

    for (std::size_t point_index = 0; point_index < hermite255_points;
         ++point_index) {
        std::array<std::uint16_t, hermite255_coefficient_count> values{};
        for (std::size_t index = 0; index < nodes.size(); ++index) {
            values[index] = evaluate_scalar_bsgs(
                instance.polynomial,
                instance.points[point_index] ^ nodes[index], field);
        }
        const DensePolynomial255 interpolated =
            interpolate_newton(nodes, values, inverse_denominators, field);
        const DensePolynomial255 expected = shifted_coefficients(
            instance.polynomial, instance.points[point_index], field);
        result.full_shift_polynomials_match =
            result.full_shift_polynomials_match && interpolated == expected;
        for (std::size_t order = 0; order < hermite255_jet_length; ++order)
            result.symbols[point_index][order] = interpolated[order];
    }
    return result;
}

[[nodiscard]] inline HermiteBatch evaluate_coefficient_forward(
    const Hermite255Instance& instance, const BinaryField16& field) {
    HermiteBatch current{};
    for (std::size_t point = 0; point < hermite255_points; ++point)
        current[point][0] = instance.polynomial[hermite255_degree];

    std::size_t processed_coefficients = 1;
    for (int coefficient_index = static_cast<int>(hermite255_degree) - 1;
         coefficient_index >= 0; --coefficient_index) {
        HermiteBatch next{};
        const std::size_t maximum_existing_order =
            std::min<std::size_t>(processed_coefficients - 1,
                                  hermite255_jet_length - 1);
        for (std::size_t point = 0; point < hermite255_points; ++point) {
            for (std::size_t order = 0; order <= maximum_existing_order;
                 ++order) {
                next[point][order] = field.multiply(
                    current[point][order], instance.points[point]);
                if (order != 0)
                    next[point][order] ^= current[point][order - 1];
            }
            next[point][0] ^=
                instance.polynomial[static_cast<std::size_t>(coefficient_index)];
            if (processed_coefficients < hermite255_jet_length) {
                next[point][processed_coefficients] =
                    current[point][processed_coefficients - 1];
            }
        }
        current = next;
        ++processed_coefficients;
    }
    return current;
}

}  // namespace detail

struct Hermite255FunctionalResult {
    HermiteBatch oracle{};
    LocalSimdCodec8224::Batch local_simd{};
    LocalSimdCodec8224::Batch local_simd_expected{};
    HermiteBatch reduced_direct_hasse{};
    HermiteBatch reduced_evaluation_interpolation{};
    HermiteBatch coefficient_separated_forward{};
    bool interpolation_full_polynomial_match = false;
    Hermite255CircuitSuite circuits{};

    [[nodiscard]] bool local_simd_correct() const noexcept {
        return local_simd == local_simd_expected;
    }

    [[nodiscard]] bool all_correct() const noexcept {
        return local_simd_correct() && reduced_direct_hasse == oracle &&
               reduced_evaluation_interpolation == oracle &&
               coefficient_separated_forward == oracle &&
               interpolation_full_polynomial_match;
    }
};

[[nodiscard]] inline Hermite255FunctionalResult run_hermite255_functional(
    const LocalSimdCodec8224& codec, const Hermite255Instance& instance) {
    const LocalFieldIsomorphisms maps(codec);
    const BinaryField16 source_field(maps.source_modulus());

    Hermite255FunctionalResult result;
    result.oracle = hasse_oracle(instance, source_field);
    result.local_simd =
        detail::evaluate_local_bsgs(codec, maps, instance);
    for (std::size_t slot = 0; slot < hermite255_points; ++slot) {
        for (std::size_t order = 0; order < hermite255_jet_length; ++order) {
            result.local_simd_expected[slot][order] =
                maps.map(slot, result.oracle[slot][order]);
        }
    }

    const ReducedSimdVector reduced =
        detail::evaluate_reduced_direct_hasse(instance, source_field);
    for (std::size_t point = 0; point < hermite255_points; ++point) {
        for (std::size_t order = 0; order < hermite255_jet_length; ++order) {
            result.reduced_direct_hasse[point][order] =
                reduced[point * hermite255_jet_length + order];
        }
    }

    const detail::InterpolationResult interpolation =
        detail::evaluate_interpolation_baseline(instance, source_field);
    result.reduced_evaluation_interpolation = interpolation.symbols;
    result.interpolation_full_polynomial_match =
        interpolation.full_shift_polynomials_match;
    result.coefficient_separated_forward =
        detail::evaluate_coefficient_forward(instance, source_field);
    result.circuits = compile_hermite255_circuits();
    return result;
}

}  // namespace nilhe::jet::workloads
