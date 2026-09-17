#pragma once

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <utility>

namespace nilhe::jet::workloads {

// A scheme-independent accounting record for public arithmetic circuits.  The
// depth below counts ciphertext--ciphertext multiplication layers only.
// Ciphertext--plaintext products are recorded separately because their level
// and noise costs depend on the concrete exact-RLWE backend.
struct CircuitCost {
    std::string schedule;
    std::size_t ciphertext_multiplications = 0;
    std::size_t ciphertext_plaintext_multiplications = 0;
    std::size_t ciphertext_additions = 0;
    std::size_t plaintext_additions = 0;
    std::size_t ciphertext_multiplicative_depth = 0;
    std::size_t maximum_parallel_multiplications = 0;
    std::size_t input_ciphertexts = 0;
    std::size_t output_ciphertexts_before_compaction = 0;
    bool needs_cross_slot_linear_map = false;
};

struct CircuitWire {
    std::size_t multiplication_depth = 0;
};

// Small accounting IR used by the Hermite-255 compiler.  It intentionally
// models only public circuit structure: it never inspects plaintext data.
class CircuitCostBuilder {
  public:
    explicit CircuitCostBuilder(std::string schedule) {
        cost_.schedule = std::move(schedule);
    }

    [[nodiscard]] CircuitWire input() const noexcept { return {}; }

    [[nodiscard]] CircuitWire multiply(CircuitWire left,
                                       CircuitWire right) {
        ++cost_.ciphertext_multiplications;
        CircuitWire result{
            std::max(left.multiplication_depth, right.multiplication_depth) + 1};
        cost_.ciphertext_multiplicative_depth = std::max(
            cost_.ciphertext_multiplicative_depth,
            result.multiplication_depth);
        return result;
    }

    [[nodiscard]] CircuitWire multiply_plain(CircuitWire value) {
        ++cost_.ciphertext_plaintext_multiplications;
        return value;
    }

    [[nodiscard]] CircuitWire add(CircuitWire left, CircuitWire right) {
        ++cost_.ciphertext_additions;
        return {std::max(left.multiplication_depth,
                         right.multiplication_depth)};
    }

    [[nodiscard]] CircuitWire add_plain(CircuitWire value) {
        ++cost_.plaintext_additions;
        return value;
    }

    CircuitCost& cost() noexcept { return cost_; }
    const CircuitCost& cost() const noexcept { return cost_; }

  private:
    CircuitCost cost_;
};

// Compile a degree-255 polynomial as sixteen degree-15 baby polynomials and a
// balanced radix-16 giant-step tree.  All 256 public coefficients are assumed
// potentially nonzero.  Powers x^2,...,x^16 use the balanced recurrence
// x^e=x^floor(e/2)x^ceil(e/2), so their maximum multiplication depth is four.
inline CircuitCost compile_dense_degree255_bsgs(
    const std::string& schedule_name) {
    CircuitCostBuilder builder(schedule_name);
    CircuitWire powers[17]{};
    powers[1] = builder.input();
    for (std::size_t exponent = 2; exponent <= 16; ++exponent) {
        powers[exponent] = builder.multiply(
            powers[exponent / 2], powers[(exponent + 1) / 2]);
    }

    CircuitWire blocks[16]{};
    for (std::size_t block = 0; block < 16; ++block) {
        // The degree-zero coefficient is added as plaintext.  Every remaining
        // public coefficient scales one encrypted baby power.
        CircuitWire accumulator = builder.multiply_plain(powers[1]);
        for (std::size_t degree = 2; degree < 16; ++degree) {
            const CircuitWire term = builder.multiply_plain(powers[degree]);
            accumulator = builder.add(accumulator, term);
        }
        accumulator = builder.add_plain(accumulator);
        blocks[block] = accumulator;
    }

    CircuitWire giant_powers[4]{};
    giant_powers[0] = powers[16];
    for (std::size_t level = 1; level < 4; ++level) {
        giant_powers[level] = builder.multiply(
            giant_powers[level - 1], giant_powers[level - 1]);
    }

    std::size_t width = 16;
    for (std::size_t level = 0; level < 4; ++level) {
        const std::size_t next_width = width / 2;
        for (std::size_t index = 0; index < next_width; ++index) {
            const CircuitWire high = builder.multiply(
                blocks[2 * index + 1], giant_powers[level]);
            blocks[index] = builder.add(blocks[2 * index], high);
        }
        width = next_width;
    }

    CircuitCost result = builder.cost();
    result.maximum_parallel_multiplications = 8;
    result.input_ciphertexts = 1;
    result.output_ciphertexts_before_compaction = 1;
    if (result.ciphertext_multiplications != 33 ||
        result.ciphertext_multiplicative_depth != 8) {
        throw std::logic_error("degree-255 BSGS compiler invariant failed");
    }
    return result;
}

inline CircuitCost compile_coefficient_separated_forward() {
    CircuitCost result;
    result.schedule = "coefficient-separated-forward";
    // Start from the public leading coefficient.  At Horner step s, exactly
    // min(s,16) coefficient ciphertexts are live before multiplication by the
    // encrypted point.  The newly exposed highest coefficient is a copy, not
    // a multiplication.
    for (std::size_t step = 1; step <= 255; ++step) {
        const std::size_t active = std::min<std::size_t>(step, 16);
        result.ciphertext_multiplications += active;
        result.ciphertext_additions += active - 1;
        ++result.plaintext_additions;
    }
    result.ciphertext_multiplicative_depth = 255;
    result.maximum_parallel_multiplications = 16;
    result.input_ciphertexts = 1;
    result.output_ciphertexts_before_compaction = 16;
    if (result.ciphertext_multiplications != 3960)
        throw std::logic_error("coefficient-forward compiler invariant failed");
    return result;
}

struct Hermite255CircuitSuite {
    CircuitCost local_simd;
    CircuitCost reduced_direct_hasse;
    CircuitCost reduced_evaluation_interpolation;
    CircuitCost coefficient_separated_forward;
};

inline Hermite255CircuitSuite compile_hermite255_circuits() {
    Hermite255CircuitSuite suite;
    suite.local_simd =
        compile_dense_degree255_bsgs("local-simd-radix16-bsgs");
    suite.reduced_direct_hasse =
        compile_dense_degree255_bsgs("reduced-simd-direct-hasse-bsgs");

    const CircuitCost one_interpolation_evaluation =
        compile_dense_degree255_bsgs("reduced-simd-evaluation-interpolation");
    suite.reduced_evaluation_interpolation = one_interpolation_evaluation;
    suite.reduced_evaluation_interpolation.ciphertext_multiplications *= 16;
    suite.reduced_evaluation_interpolation
        .ciphertext_plaintext_multiplications *= 16;
    suite.reduced_evaluation_interpolation.ciphertext_additions *= 16;
    suite.reduced_evaluation_interpolation.plaintext_additions *= 16;
    suite.reduced_evaluation_interpolation.maximum_parallel_multiplications =
        16 * one_interpolation_evaluation.maximum_parallel_multiplications;
    suite.reduced_evaluation_interpolation.input_ciphertexts = 16;
    suite.reduced_evaluation_interpolation
        .output_ciphertexts_before_compaction = 16;
    suite.reduced_evaluation_interpolation.needs_cross_slot_linear_map = true;

    suite.coefficient_separated_forward =
        compile_coefficient_separated_forward();
    return suite;
}

}  // namespace nilhe::jet::workloads
