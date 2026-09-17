#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "jet_hermite255.hpp"

namespace {

void check(bool condition, const char* description, int& failures) {
    if (!condition) {
        ++failures;
        std::printf("  [FAIL] %s\n", description);
    }
}

}  // namespace

int main() {
    using namespace nilhe::jet;
    using namespace nilhe::jet::workloads;

    int failures = 0;
    const LocalSimdCodec8224 codec;
    const LocalFieldIsomorphisms maps(codec);
    const BinaryField16 source(maps.source_modulus());
    const Hermite255Instance instance = Hermite255Instance::deterministic();

    check(local_simd_carrier.ring_dimension ==
              reduced_simd_carrier.ring_dimension,
          "ramified and reduced carriers have equal dimension", failures);
    check(local_simd_carrier.residue_degree ==
              reduced_simd_carrier.residue_degree,
          "ramified and reduced carriers have equal residue degree", failures);
    check(local_simd_carrier.completed_jet_capacity ==
              reduced_simd_carrier.completed_jet_capacity,
          "both carriers hold sixteen completed length-16 jets", failures);
    check(reduced_simd_carrier.field_slots == hermite255_outputs,
          "reduced carrier has exactly 256 field slots", failures);

    bool dense = true;
    for (std::uint16_t coefficient : instance.polynomial)
        dense = dense && coefficient != 0;
    check(dense, "fixed degree-255 polynomial is dense", failures);
    check(instance.polynomial[hermite255_degree] != 0,
          "fixed polynomial has exact degree 255", failures);
    bool distinct_points = true;
    for (std::size_t left = 0; left < hermite255_points; ++left) {
        for (std::size_t right = left + 1; right < hermite255_points; ++right)
            distinct_points = distinct_points &&
                              instance.points[left] != instance.points[right];
    }
    check(distinct_points, "sixteen private-point fixtures are distinct", failures);

    // Independently check that every coefficient-field map preserves the field
    // operations used by the workload.  These values intentionally include
    // both sparse and dense polynomial representatives.
    constexpr std::uint16_t samples[][2] = {
        {0x0001u, 0x0002u}, {0x1234u, 0xabcdu},
        {0xffffu, 0x00f1u}, {0x8001u, 0x7ffeu}};
    bool maps_are_homomorphisms = true;
    for (std::size_t slot = 0; slot < hermite255_points; ++slot) {
        const BinaryField16 target(maps.target_modulus(slot));
        for (const auto& pair : samples) {
            maps_are_homomorphisms = maps_are_homomorphisms &&
                maps.map(slot, source.add(pair[0], pair[1])) ==
                    target.add(maps.map(slot, pair[0]),
                               maps.map(slot, pair[1])) &&
                maps.map(slot, source.multiply(pair[0], pair[1])) ==
                    target.multiply(maps.map(slot, pair[0]),
                                    maps.map(slot, pair[1]));
        }
    }
    check(maps_are_homomorphisms,
          "all sixteen coefficient-field embeddings preserve + and *",
          failures);

    const Hermite255FunctionalResult result =
        run_hermite255_functional(codec, instance);
    check(result.local_simd_correct(),
          "Local-SIMD BSGS jet evaluation matches independent Hasse oracle",
          failures);
    check(codec.decode(codec.encode(result.local_simd)) == result.local_simd,
          "Local-SIMD workload result survives concrete Phi_8224 codec",
          failures);
    check(result.reduced_direct_hasse == result.oracle,
          "reduced direct-Hasse SIMD schedule matches oracle", failures);
    check(result.reduced_evaluation_interpolation == result.oracle,
          "reduced 256-point evaluation/interpolation matches oracle", failures);
    check(result.interpolation_full_polynomial_match,
          "interpolation recovers all 256 shifted-polynomial coefficients",
          failures);
    check(result.coefficient_separated_forward == result.oracle,
          "coefficient-separated forward propagation matches oracle", failures);
    check(result.all_correct(), "all output-matched schedules agree", failures);

    const CircuitCost& local = result.circuits.local_simd;
    const CircuitCost& direct = result.circuits.reduced_direct_hasse;
    const CircuitCost& interpolation =
        result.circuits.reduced_evaluation_interpolation;
    const CircuitCost& forward =
        result.circuits.coefficient_separated_forward;
    check(local.ciphertext_multiplications == 33 &&
              local.ciphertext_multiplicative_depth == 8,
          "Local-SIMD compiler emits 33 HMul at depth 8", failures);
    check(local.ciphertext_plaintext_multiplications == 240,
          "Local-SIMD compiler emits 240 public-coefficient products", failures);
    check(direct.ciphertext_multiplications ==
              local.ciphertext_multiplications &&
              direct.ciphertext_multiplicative_depth ==
                  local.ciphertext_multiplicative_depth,
          "direct-Hasse reduced SIMD has the same nonlinear circuit count",
          failures);
    check(interpolation.ciphertext_multiplications == 528 &&
              interpolation.ciphertext_multiplicative_depth == 8 &&
              interpolation.input_ciphertexts == 16 &&
              interpolation.needs_cross_slot_linear_map,
          "evaluation/interpolation count and linear-map gate are explicit",
          failures);
    check(forward.ciphertext_multiplications == 3960 &&
              forward.ciphertext_multiplicative_depth == 255 &&
              forward.output_ciphertexts_before_compaction == 16,
          "sparsity-aware coefficient-forward count is exact", failures);

    std::printf("Hermite-255 output-matched functional tranche\n");
    std::printf("  workload: one dense degree-255 polynomial, 16 points, "
                "16 Hasse coefficients/point\n");
    std::printf("  useful outputs: %zu F_(2^16) elements\n",
                hermite255_outputs);
    std::printf("  Local-SIMD: %zu HMul, depth %zu, 1 Phi_8224 carrier\n",
                local.ciphertext_multiplications,
                local.ciphertext_multiplicative_depth);
    std::printf("  reduced direct Hasse: %zu HMul, depth %zu, "
                "1 semantic Phi_4369 carrier\n",
                direct.ciphertext_multiplications,
                direct.ciphertext_multiplicative_depth);
    std::printf("  reduced evaluation/interpolation: %zu HMul, depth %zu, "
                "16 semantic Phi_4369 carriers + unfused linear maps\n",
                interpolation.ciphertext_multiplications,
                interpolation.ciphertext_multiplicative_depth);
    std::printf("  coefficient forward: %zu HMul, depth %zu, "
                "16 coefficient ciphertexts\n",
                forward.ciphertext_multiplications,
                forward.ciphertext_multiplicative_depth);
    std::printf("  evidence class: plaintext/compiler/oracle functional only\n");
    std::printf("  encrypted reduced carrier: not implemented\n");
    std::printf("  security match: not established\n");
    std::printf("  timing claim: prohibited by manifest\n");
    std::printf("  checks: %s\n", failures == 0 ? "pass" : "fail");
    return failures == 0 ? 0 : 1;
}
