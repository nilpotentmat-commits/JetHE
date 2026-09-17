#pragma once

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace nilhe::jet {

// Concrete plaintext codec for
//   F_2[X]/(Phi_8224) = F_2[X]/(Phi_257(X)^16)
//     = product_i F_(2^16)[epsilon_i]/(epsilon_i^16).
// Binary polynomials are stored coefficient-first in a fixed bitset.  A
// product of two reduced degree-4095 representatives has degree at most 8190.
class LocalSimdCodec8224 {
  public:
    static constexpr std::size_t polynomial_capacity = 8193;
    using BinaryPolynomial = std::bitset<polynomial_capacity>;
    static constexpr std::size_t slot_count = 16;
    static constexpr std::size_t residue_degree = 16;
    static constexpr std::size_t jet_length = 16;
    static constexpr std::size_t ring_dimension = 4096;
    using Jet = std::array<std::uint16_t, jet_length>;
    using Batch = std::array<Jet, slot_count>;

    LocalSimdCodec8224() : global_modulus_(phi8224_mod_two()) {
        const auto discovered = factor_phi257();
        if (discovered.size() != slot_count)
            throw std::runtime_error("Phi_257 did not split into sixteen degree-16 factors");

        for (std::size_t slot = 0; slot < slot_count; ++slot) {
            factors_[slot] = from_u64(discovered[slot]);
            local_moduli_[slot] = frobenius_power_16(factors_[slot]);
            const BinaryPolynomial complement =
                exact_divide(global_modulus_, local_moduli_[slot]);
            const BinaryPolynomial inverse = invert_mod(
                reduce(complement, local_moduli_[slot]), local_moduli_[slot]);
            idempotents_[slot] = reduce(
                multiply(complement, inverse), global_modulus_);
        }
    }

    [[nodiscard]] const BinaryPolynomial& global_modulus() const {
        return global_modulus_;
    }

    [[nodiscard]] std::uint32_t factor(std::size_t slot) const {
        require_slot(slot);
        return static_cast<std::uint32_t>(to_u64(factors_[slot]));
    }

    [[nodiscard]] BinaryPolynomial encode(const Batch& batch) const {
        BinaryPolynomial encoded;
        for (std::size_t slot = 0; slot < slot_count; ++slot) {
            BinaryPolynomial local;
            BinaryPolynomial epsilon_power = from_u64(1);
            for (std::size_t degree = 0; degree < jet_length; ++degree) {
                const BinaryPolynomial lift = teichmueller_lift(
                    from_u64(batch[slot][degree]), slot);
                local ^= multiply(lift, epsilon_power);
                epsilon_power = multiply(epsilon_power, factors_[slot]);
            }
            local = reduce(local, local_moduli_[slot]);
            encoded ^= multiply_mod(local, idempotents_[slot], global_modulus_);
        }
        return reduce(encoded, global_modulus_);
    }

    [[nodiscard]] Batch decode(const BinaryPolynomial& polynomial) const {
        Batch decoded{};
        const BinaryPolynomial normalized = reduce(polynomial, global_modulus_);
        for (std::size_t slot = 0; slot < slot_count; ++slot) {
            BinaryPolynomial local = reduce(normalized, local_moduli_[slot]);
            BinaryPolynomial remaining_modulus = local_moduli_[slot];
            for (std::size_t degree = 0; degree < jet_length; ++degree) {
                const BinaryPolynomial residue = reduce(local, factors_[slot]);
                decoded[slot][degree] = polynomial_to_u16(residue);
                local ^= reduce(teichmueller_lift(residue, slot),
                                remaining_modulus);
                local = exact_divide(local, factors_[slot]);
                remaining_modulus = exact_divide(remaining_modulus,
                                                 factors_[slot]);
                if (remaining_modulus == from_u64(1))
                    local.reset();
                else
                    local = reduce(local, remaining_modulus);
            }
            if (local.any())
                throw std::runtime_error("local jet decoder left a nonzero quotient");
        }
        return decoded;
    }

    [[nodiscard]] Batch multiply_oracle(const Batch& left,
                                        const Batch& right) const {
        Batch result{};
        for (std::size_t slot = 0; slot < slot_count; ++slot) {
            const std::uint32_t modulus = factor(slot);
            for (std::size_t degree = 0; degree < jet_length; ++degree) {
                for (std::size_t left_degree = 0;
                     left_degree <= degree; ++left_degree) {
                    result[slot][degree] ^= field_multiply(
                        left[slot][left_degree],
                        right[slot][degree - left_degree], modulus);
                }
            }
        }
        return result;
    }

    [[nodiscard]] static bool coefficient(const BinaryPolynomial& polynomial,
                                          std::size_t degree) {
        return polynomial.test(degree);
    }

    [[nodiscard]] static int polynomial_degree(
        const BinaryPolynomial& polynomial) {
        return degree(polynomial);
    }

    [[nodiscard]] static BinaryPolynomial ring_multiply(
        const BinaryPolynomial& left, const BinaryPolynomial& right) {
        return multiply(left, right);
    }

  private:
    std::array<BinaryPolynomial, slot_count> factors_{};
    std::array<BinaryPolynomial, slot_count> local_moduli_{};
    std::array<BinaryPolynomial, slot_count> idempotents_{};
    BinaryPolynomial global_modulus_;

    static void require_slot(std::size_t slot) {
        if (slot >= slot_count)
            throw std::out_of_range("Local-SIMD slot index");
    }

    [[nodiscard]] static int degree(const BinaryPolynomial& polynomial) {
        for (std::size_t index = polynomial_capacity; index-- > 0;) {
            if (polynomial.test(index))
                return static_cast<int>(index);
        }
        return -1;
    }

    [[nodiscard]] static BinaryPolynomial multiply(
        const BinaryPolynomial& left, const BinaryPolynomial& right) {
        BinaryPolynomial product;
        for (std::size_t bit = 0; bit < polynomial_capacity; ++bit) {
            if (right.test(bit))
                product ^= left << bit;
        }
        return product;
    }

    [[nodiscard]] static std::pair<BinaryPolynomial, BinaryPolynomial> divmod(
        const BinaryPolynomial& dividend, const BinaryPolynomial& divisor) {
        if (divisor.none())
            throw std::invalid_argument("binary-polynomial division by zero");
        BinaryPolynomial quotient;
        BinaryPolynomial remainder = dividend;
        const int divisor_degree = degree(divisor);
        while (degree(remainder) >= divisor_degree) {
            const unsigned shift = static_cast<unsigned>(
                degree(remainder) - divisor_degree);
            quotient.flip(shift);
            remainder ^= divisor << shift;
        }
        return {quotient, remainder};
    }

    [[nodiscard]] static BinaryPolynomial reduce(
        const BinaryPolynomial& polynomial, const BinaryPolynomial& modulus) {
        return divmod(polynomial, modulus).second;
    }

    [[nodiscard]] static BinaryPolynomial exact_divide(
        const BinaryPolynomial& dividend, const BinaryPolynomial& divisor) {
        auto result = divmod(dividend, divisor);
        if (result.second.any())
            throw std::runtime_error("inexact binary-polynomial division");
        return result.first;
    }

    [[nodiscard]] static BinaryPolynomial multiply_mod(
        const BinaryPolynomial& left, const BinaryPolynomial& right,
        const BinaryPolynomial& modulus) {
        return reduce(multiply(left, right), modulus);
    }

    [[nodiscard]] static BinaryPolynomial invert_mod(
        const BinaryPolynomial& element, const BinaryPolynomial& modulus) {
        BinaryPolynomial old_remainder = modulus;
        BinaryPolynomial remainder = element;
        BinaryPolynomial old_coefficient;
        BinaryPolynomial coefficient = from_u64(1);
        while (remainder.any()) {
            const auto quotient_remainder = divmod(old_remainder, remainder);
            const BinaryPolynomial next_remainder = quotient_remainder.second;
            const BinaryPolynomial next_coefficient =
                old_coefficient ^ multiply(quotient_remainder.first, coefficient);
            old_remainder = remainder;
            remainder = next_remainder;
            old_coefficient = coefficient;
            coefficient = next_coefficient;
        }
        if (old_remainder != from_u64(1))
            throw std::runtime_error("noninvertible CRT complement");
        return reduce(old_coefficient, modulus);
    }

    [[nodiscard]] static BinaryPolynomial phi257() {
        BinaryPolynomial result;
        for (std::size_t exponent = 0; exponent <= 256; ++exponent)
            result.set(exponent);
        return result;
    }

    [[nodiscard]] static BinaryPolynomial phi8224_mod_two() {
        BinaryPolynomial result;
        for (std::size_t exponent = 0; exponent <= 256; ++exponent)
            result.set(16 * exponent);
        return result;
    }

    [[nodiscard]] static BinaryPolynomial frobenius_power_16(
        const BinaryPolynomial& polynomial) {
        BinaryPolynomial result;
        for (int exponent = 0; exponent <= degree(polynomial); ++exponent) {
            if (polynomial.test(static_cast<std::size_t>(exponent)))
                result.set(16 * static_cast<std::size_t>(exponent));
        }
        return result;
    }

    [[nodiscard]] static std::vector<std::uint32_t> factor_phi257() {
        std::vector<std::uint32_t> factors;
        const BinaryPolynomial polynomial = phi257();
        for (std::uint32_t candidate = (std::uint32_t{1} << 16) | 1u;
             candidate < (std::uint32_t{1} << 17); candidate += 2) {
            const BinaryPolynomial factor_polynomial = from_u64(candidate);
            if (reduce(polynomial, factor_polynomial).none())
                factors.push_back(candidate);
        }
        return factors;
    }

    [[nodiscard]] BinaryPolynomial teichmueller_lift(
        BinaryPolynomial residue, std::size_t slot) const {
        require_slot(slot);
        residue = reduce(residue, factors_[slot]);
        for (std::size_t iteration = 0; iteration < residue_degree; ++iteration)
            residue = multiply_mod(residue, residue, local_moduli_[slot]);
        return residue;
    }

    [[nodiscard]] static std::uint16_t polynomial_to_u16(
        const BinaryPolynomial& polynomial) {
        if (degree(polynomial) >= static_cast<int>(residue_degree))
            throw std::overflow_error("field residue exceeds sixteen bits");
        return static_cast<std::uint16_t>(to_u64(polynomial));
    }

    [[nodiscard]] static std::uint16_t field_multiply(
        std::uint16_t left, std::uint16_t right, std::uint32_t modulus) {
        std::uint32_t product = 0;
        for (std::size_t bit = 0; bit < residue_degree; ++bit) {
            if (((right >> bit) & 1u) != 0)
                product ^= static_cast<std::uint32_t>(left) << bit;
        }
        for (int exponent = static_cast<int>(2 * residue_degree - 2);
             exponent >= static_cast<int>(residue_degree); --exponent) {
            if ((product & (std::uint32_t{1} << exponent)) != 0)
                product ^= modulus << (exponent - residue_degree);
        }
        return static_cast<std::uint16_t>(product);
    }

    [[nodiscard]] static BinaryPolynomial from_u64(std::uint64_t value) {
        BinaryPolynomial result;
        for (std::size_t bit = 0; bit < 64; ++bit) {
            if (((value >> bit) & 1u) != 0)
                result.set(bit);
        }
        return result;
    }

    [[nodiscard]] static std::uint64_t to_u64(
        const BinaryPolynomial& polynomial) {
        std::uint64_t result = 0;
        for (std::size_t bit = 0; bit < 64; ++bit) {
            if (polynomial.test(bit))
                result |= std::uint64_t{1} << bit;
        }
        return result;
    }
};

}  // namespace nilhe::jet
