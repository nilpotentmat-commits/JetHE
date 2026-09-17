#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif
#include "pke/openfhe.h"
#include "pke/ciphertext-ser.h"
#include "pke/cryptocontext-ser.h"
#include "pke/key/key-ser.h"
#include "core/version.h"

namespace {
using Clock = std::chrono::steady_clock;
using Context = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;
using Ciphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using U64 = std::uint64_t;
using Polynomial = std::vector<U64>;
constexpr U64 packed_prime = 65537;

struct Config {
    std::string scheme = "BGV", layout = "native", schedule = "sequential";
    std::size_t length = 4, mults = 1, jobs = 1, repetitions = 5;
    U64 seed = 11;
    bool self_test = false;
};
struct Trial {
    double encode_ms{}, encrypt_ms{}, eval_ms{}, decrypt_ms{}, decode_ms{};
    std::size_t ctct_calls{}, ctct_depth{};
    std::vector<Polynomial> decoded_outputs;
};
struct Node { Ciphertext ciphertext; std::size_t depth{}; };
struct FailureDetails {
    bool active = false;
    Config config;
    std::string stage = "configuration";
    std::size_t ring_dimension{}, q_bits{}, parameter_depth{}, actual_depth{};
    std::size_t trial_index{}, job_index{}, decoded_coefficient_count{};
    Polynomial actual, expected;
} failure;

double elapsed(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}
std::string escape(const std::string& input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c == '\n') out << "\\n";
        else if (c == '\r') out << "\\r";
        else if (c == '\t') out << "\\t";
        else if (c < 32) out << '?';
        else out << c;
    }
    return out.str();
}
U64 integer(const std::string& value) {
    if (value.empty() || value.front() == '-') throw std::invalid_argument("expected a nonnegative integer");
    std::size_t consumed = 0;
    const U64 result = std::stoull(value, &consumed);
    if (consumed != value.size()) throw std::invalid_argument("invalid integer suffix");
    return result;
}
void print_polynomial(const Polynomial& a) {
    std::cout << '[';
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (i) std::cout << ',';
        std::cout << a[i];
    }
    std::cout << ']';
}
Config parse(int argc, char** argv) {
    Config c;
    for (int i = 1; i < argc; ++i) {
        const std::string option = argv[i];
        if (option == "--self-test") { c.self_test = true; continue; }
        if (++i >= argc) throw std::invalid_argument("missing argument value");
        const std::string value = argv[i];
        if (option == "--scheme") c.scheme = value;
        else if (option == "--layout") c.layout = value;
        else if (option == "--schedule") c.schedule = value;
        else if (option == "--length") c.length = integer(value);
        else if (option == "--mults") c.mults = integer(value);
        else if (option == "--jobs") c.jobs = integer(value);
        else if (option == "--repetitions") c.repetitions = integer(value);
        else if (option == "--seed") c.seed = integer(value);
        else throw std::invalid_argument("unknown option " + option);
    }
    if (c.scheme != "BGV" && c.scheme != "BFV") throw std::invalid_argument("scheme must be BGV or BFV");
    if (c.layout != "native" && c.layout != "packed_terminal") throw std::invalid_argument("invalid layout");
    if (c.schedule != "sequential" && c.schedule != "balanced") throw std::invalid_argument("invalid schedule");
    if (c.length != 4 && c.length != 8 && c.length != 16) throw std::invalid_argument("length must be 4, 8, or 16");
    if (c.mults != 1 && c.mults != 2 && c.mults != 4) throw std::invalid_argument("mults must be 1, 2, or 4");
    if (c.jobs == 0 || c.repetitions == 0) throw std::invalid_argument("jobs and repetitions must be positive");
    return c;
}
std::size_t ceil_log2(std::size_t n) {
    std::size_t depth = 0, power = 1;
    while (power < n) { power *= 2; ++depth; }
    return depth;
}
U64 binomial(std::size_t n, std::size_t k) {
    k = std::min(k, n - k);
    U64 value = 1;
    for (std::size_t j = 1; j <= k; ++j) {
        if (value > std::numeric_limits<U64>::max() / (n - k + j))
            throw std::overflow_error("binomial bound overflow");
        value = value * (n - k + j) / j;
    }
    return value;
}
void validate_lift(std::size_t length, std::size_t mults, U64 prime) {
    const std::size_t points = (mults + 1) * (length - 1) + 1;
    if (points > prime || binomial(length - 1 + mults, mults) >= prime)
        throw std::invalid_argument("packed terminal integer-lift bound or point count fails");
}
U64 power_mod(U64 a, U64 n, U64 p) {
    U64 value = 1;
    while (n) { if (n & 1) value = value * a % p; a = a * a % p; n >>= 1; }
    return value;
}
std::vector<Polynomial> interpolation_weights(std::size_t points, std::size_t length, U64 p) {
    // Invert the full Vandermonde before retaining the low-coefficient rows.
    std::vector<Polynomial> a(points, Polynomial(2 * points));
    for (std::size_t row = 0; row < points; ++row) {
        U64 value = 1;
        for (std::size_t column = 0; column < points; ++column) {
            a[row][column] = value;
            value = value * (row + 1) % p;
        }
        a[row][points + row] = 1;
    }
    for (std::size_t column = 0; column < points; ++column) {
        std::size_t pivot = column;
        while (pivot < points && a[pivot][column] == 0) ++pivot;
        if (pivot == points) throw std::runtime_error("singular interpolation matrix");
        std::swap(a[column], a[pivot]);
        const U64 inverse = power_mod(a[column][column], p - 2, p);
        for (auto& x : a[column]) x = x * inverse % p;
        for (std::size_t row = 0; row < points; ++row) {
            if (row == column) continue;
            const U64 factor = a[row][column];
            for (std::size_t j = 0; j < 2 * points; ++j)
                a[row][j] = (a[row][j] + p - factor * a[column][j] % p) % p;
        }
    }
    std::vector<Polynomial> result(length, Polynomial(points));
    for (std::size_t row = 0; row < length; ++row)
        std::copy(a[row].begin() + points, a[row].end(), result[row].begin());
    return result;
}
Polynomial binary_product(const Polynomial& a, const Polynomial& b) {
    Polynomial result(a.size());
    for (std::size_t j = 0; j < a.size(); ++j)
        for (std::size_t k = 0; k <= j; ++k) result[j] ^= a[k] & b[j - k];
    return result;
}
U64 evaluate(const Polynomial& a, U64 point, U64 p) {
    U64 result = 0;
    for (auto i = a.rbegin(); i != a.rend(); ++i) result = (result * point + *i) % p;
    return result;
}
std::vector<std::int64_t> encode_native(const Polynomial& a, std::size_t n) {
    std::vector<std::int64_t> result(n);
    for (std::size_t j = 0; j < a.size(); ++j)
        if (a[j]) for (std::size_t k = 0; k <= j; ++k)
            if ((k & ~j) == 0) result[k] ^= 1;
    return result;
}
Polynomial decode_native(const std::vector<std::int64_t>& a, std::size_t length) {
    Polynomial result(length);
    for (std::size_t j = 0; j < a.size(); ++j)
        if (a[j] % 2 != 0) for (std::size_t k = 0; k < length && k <= j; ++k)
            if ((k & ~j) == 0) result[k] ^= 1;
    return result;
}
U64 canonical(std::int64_t x, U64 p) {
    const auto residue = x % static_cast<std::int64_t>(p);
    return residue < 0 ? static_cast<U64>(residue + p) : static_cast<U64>(residue);
}
class CountingStreambuf final : public std::streambuf {
  public: std::size_t bytes{};
  protected:
    std::streamsize xsputn(const char*, std::streamsize n) override {
        if (n > 0) bytes += static_cast<std::size_t>(n);
        return n;
    }
    int_type overflow(int_type c) override {
        if (!traits_type::eq_int_type(c, traits_type::eof())) ++bytes;
        return traits_type::not_eof(c);
    }
};
template<class T> std::size_t serialized_bytes(const T& item) {
    CountingStreambuf sink;
    std::ostream stream(&sink);
    lbcrypto::Serial::Serialize(item, stream, lbcrypto::SerType::BINARY);
    if (!stream) throw std::runtime_error("serialization failed");
    return sink.bytes;
}
std::size_t peak_rss() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS counters{};
    counters.cb = sizeof(counters);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters)))
        return static_cast<std::size_t>(counters.PeakWorkingSetSize);
#endif
    return 0;
}
Context make_context(const Config& c, std::size_t depth) {
    using namespace lbcrypto;
    const U64 p = c.layout == "native" ? 2 : packed_prime;
    Context context;
    if (c.scheme == "BGV") {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetPlaintextModulus(p);
        parameters.SetMultiplicativeDepth(static_cast<std::uint32_t>(depth));
        parameters.SetSecurityLevel(HEStd_128_classic);
        context = GenCryptoContext(parameters);
    } else {
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(p);
        parameters.SetMultiplicativeDepth(static_cast<std::uint32_t>(depth));
        parameters.SetSecurityLevel(HEStd_128_classic);
        context = GenCryptoContext(parameters);
    }
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    return context;
}
Node multiply(const Context& context, const Node& a, const Node& b, std::size_t& calls) {
    ++calls;
    return {context->EvalMult(a.ciphertext, b.ciphertext), std::max(a.depth, b.depth) + 1};
}
Node circuit(const Context& context, const std::vector<Ciphertext>& inputs,
             bool balanced, std::size_t& calls) {
    if (!balanced) {
        Node state{inputs[0], 0};
        for (std::size_t i = 1; i < inputs.size(); ++i)
            state = multiply(context, state, Node{inputs[i], 0}, calls);
        return state;
    }
    std::vector<Node> current;
    for (const auto& input : inputs) current.push_back({input, 0});
    while (current.size() > 1) {
        std::vector<Node> next;
        for (std::size_t i = 0; i < current.size(); i += 2)
            next.push_back(i + 1 < current.size()
                ? multiply(context, current[i], current[i + 1], calls) : current[i]);
        current = std::move(next);
    }
    return current[0];
}
double median(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    const std::size_t n = values.size();
    return n % 2 ? values[n / 2] : (values[n / 2 - 1] + values[n / 2]) / 2;
}
void self_test() {
    const auto weights = interpolation_weights(3, 2, 17);
    std::size_t cases = 0;
    for (U64 bits = 0; bits < 16; ++bits) {
        const Polynomial a{bits & 1, (bits >> 1) & 1};
        const Polynomial b{(bits >> 2) & 1, (bits >> 3) & 1};
        const auto expected = binary_product(a, b);
        for (std::size_t j = 0; j < 2; ++j) {
            U64 value = 0;
            for (U64 point = 1; point <= 3; ++point)
                value = (value + weights[j][point - 1] * evaluate(a, point, 17)
                    % 17 * evaluate(b, point, 17)) % 17;
            if (value % 2 != expected[j]) throw std::runtime_error("terminal lift self-test fails");
        }
        if (decode_native(encode_native(a, 8), 2) != a)
            throw std::runtime_error("native basis self-test fails");
        ++cases;
    }
    bool rejected = false;
    try { validate_lift(16, 4, 17); } catch (const std::invalid_argument&) { rejected = true; }
    if (!rejected) throw std::runtime_error("unsafe integer bound accepted");
    std::cout << "{\"status\":\"PASS\",\"self_test\":true,\"exhaustive_cases\":"
              << cases << ",\"unsafe_lift_rejected\":true}\n";
}
int run(const Config& c) {
    using namespace lbcrypto;
    failure.active = true;
    failure.config = c;
    const bool native = c.layout == "native";
    const std::size_t factors = c.mults + 1;
    const std::size_t points = factors * (c.length - 1) + 1;
    const std::size_t depth = c.schedule == "balanced" ? ceil_log2(factors) : c.mults;
    // Provision both schedules for the declared sequential workload horizon.
    // Schedule comparisons therefore use a common library parameter policy.
    const std::size_t parameter_depth = c.mults;
    failure.parameter_depth = parameter_depth;
    failure.actual_depth = depth;
    validate_lift(c.length, c.mults, packed_prime);
    auto start = Clock::now();
    failure.stage = "context_and_key_setup";
    auto context = make_context(c, parameter_depth);
    auto keys = context->KeyGen();
    context->EvalMultKeyGen(keys.secretKey);
    const double setup_ms = elapsed(start);
    const auto params = context->GetCryptoParameters()->GetElementParams();
    const auto rns = std::dynamic_pointer_cast<CryptoParametersRNS>(context->GetCryptoParameters());
    if (!rns) throw std::runtime_error("missing RNS cryptoparameters");
    const std::size_t n = params->GetRingDimension();
    failure.ring_dimension = n;
    failure.q_bits = params->GetModulus().GetMSB();
    if (c.length > n) throw std::runtime_error("jet length exceeds native nilpotence index");
    if (!native && (packed_prime - 1) % (2 * n) != 0)
        throw std::runtime_error("selected dimension lacks complete F65537 batching");
    const std::size_t capacity = native ? 1 : n / points;
    if (capacity == 0) throw std::runtime_error("no complete packed job fits");
    const std::size_t batches = (c.jobs + capacity - 1) / capacity;
    start = Clock::now();
    failure.stage = "public_precomputation";
    const auto weights = native ? std::vector<Polynomial>{}
                                : interpolation_weights(points, c.length, packed_prime);
    // Explicit raw engine bits avoid implementation-dependent distributions.
    std::mt19937_64 fixture(c.seed);
    std::vector<std::vector<Polynomial>> inputs(c.jobs,
        std::vector<Polynomial>(factors, Polynomial(c.length)));
    std::vector<Polynomial> oracles(c.jobs, Polynomial(c.length));
    U64 fixture_hash = 14695981039346656037ULL;
    for (std::size_t job = 0; job < c.jobs; ++job) {
        for (auto& polynomial : inputs[job])
            for (std::size_t j = 0; j < polynomial.size(); ++j) {
                polynomial[j] = j == 0 ? 1 : fixture() & 1;
                fixture_hash = (fixture_hash ^ polynomial[j]) * 1099511628211ULL;
            }
        oracles[job] = inputs[job][0];
        for (std::size_t factor = 1; factor < factors; ++factor)
            oracles[job] = binary_product(oracles[job], inputs[job][factor]);
    }
    const double precomputation_ms = elapsed(start);
    std::vector<Trial> trials;
    std::size_t input_bytes = 0, output_bytes = 0, output_towers = 0;
    for (std::size_t repetition = 0; repetition <= c.repetitions; ++repetition) {
        failure.trial_index = repetition;
        failure.stage = "encode";
        Trial trial;
        start = Clock::now();
        std::vector<std::vector<Plaintext>> plaintexts(batches, std::vector<Plaintext>(factors));
        for (std::size_t batch = 0; batch < batches; ++batch)
            for (std::size_t factor = 0; factor < factors; ++factor) {
                if (native) {
                    plaintexts[batch][factor] = context->MakeCoefPackedPlaintext(
                        encode_native(inputs[batch][factor], n));
                } else {
                    std::vector<std::int64_t> slots(n);
                    for (std::size_t local = 0; local < capacity; ++local) {
                        const std::size_t job = batch * capacity + local;
                        if (job >= c.jobs) break;
                        for (std::size_t point = 0; point < points; ++point)
                            slots[local * points + point] = static_cast<std::int64_t>(
                                evaluate(inputs[job][factor], point + 1, packed_prime));
                    }
                    plaintexts[batch][factor] = context->MakePackedPlaintext(slots);
                }
            }
        trial.encode_ms = elapsed(start);
        failure.stage = "encrypt";
        start = Clock::now();
        std::vector<std::vector<Ciphertext>> encrypted(batches, std::vector<Ciphertext>(factors));
        for (std::size_t batch = 0; batch < batches; ++batch)
            for (std::size_t factor = 0; factor < factors; ++factor)
                encrypted[batch][factor] = context->Encrypt(keys.publicKey, plaintexts[batch][factor]);
        trial.encrypt_ms = elapsed(start);
        failure.stage = "evaluate";
        start = Clock::now();
        std::vector<Ciphertext> outputs(batches);
        for (std::size_t batch = 0; batch < batches; ++batch) {
            const auto result = circuit(context, encrypted[batch], c.schedule == "balanced", trial.ctct_calls);
            outputs[batch] = result.ciphertext;
            trial.ctct_depth = std::max(trial.ctct_depth, result.depth);
        }
        trial.eval_ms = elapsed(start);
        if (trial.ctct_calls != batches * c.mults || trial.ctct_depth != depth)
            throw std::runtime_error("executed circuit counter mismatch");
        failure.stage = "decrypt";
        start = Clock::now();
        std::vector<Plaintext> decrypted(batches);
        for (std::size_t batch = 0; batch < batches; ++batch) {
            const auto result = context->Decrypt(keys.secretKey, outputs[batch], &decrypted[batch]);
            if (!result.isValid) throw std::runtime_error("library decrypt status invalid");
            decrypted[batch]->SetLength(n);
        }
        trial.decrypt_ms = elapsed(start);
        failure.stage = "decode_and_oracle";
        start = Clock::now();
        trial.decoded_outputs.resize(c.jobs);
        for (std::size_t job = 0; job < c.jobs; ++job) {
            failure.job_index = job;
            Polynomial actual(c.length);
            if (native) {
                const auto& coefficients = decrypted[job]->GetCoefPackedValue();
                failure.decoded_coefficient_count = coefficients.size();
                if (coefficients.size() != n)
                    throw std::runtime_error("native decoder did not receive the full ring coefficient vector");
                actual = decode_native(coefficients, c.length);
            }
            else {
                const auto& values = decrypted[job / capacity]->GetPackedValue();
                const std::size_t offset = (job % capacity) * points;
                for (std::size_t coefficient = 0; coefficient < c.length; ++coefficient) {
                    U64 value = 0;
                    for (std::size_t point = 0; point < points; ++point)
                        value = (value + weights[coefficient][point]
                            * canonical(values[offset + point], packed_prime)) % packed_prime;
                    // Bound applies to each relevant integer coefficient, not to point values.
                    if (value > binomial(coefficient + c.mults, c.mults))
                        throw std::runtime_error("decoded integer coefficient violates proven bound");
                    actual[coefficient] = value & 1;
                }
            }
            if (actual != oracles[job]) {
                failure.actual = actual;
                failure.expected = oracles[job];
                throw std::runtime_error("exact binary output oracle mismatch");
            }
            trial.decoded_outputs[job] = std::move(actual);
        }
        trial.decode_ms = elapsed(start);
        if (repetition > 0) trials.push_back(trial); // Whole first trial is warmup.
        if (repetition == c.repetitions) {
            for (const auto& batch : encrypted)
                for (const auto& ct : batch) input_bytes += serialized_bytes(ct);
            for (const auto& ct : outputs) output_bytes += serialized_bytes(ct);
            output_towers = outputs[0]->GetElements()[0].GetNumOfElements();
        }
    }
    const std::size_t public_key_bytes = serialized_bytes(keys.publicKey);
    CountingStreambuf relin_sink;
    std::ostream relin_stream(&relin_sink);
    if (!context->SerializeEvalMultKey(relin_stream, SerType::BINARY, keys.secretKey->GetKeyTag()))
        throw std::runtime_error("relinearization key serialization failed");
    std::vector<double> encode_times, encrypt_times, eval_times, decrypt_times, decode_times, end_to_end;
    for (const auto& t : trials) {
        encode_times.push_back(t.encode_ms); encrypt_times.push_back(t.encrypt_ms);
        eval_times.push_back(t.eval_ms); decrypt_times.push_back(t.decrypt_ms); decode_times.push_back(t.decode_ms);
        end_to_end.push_back(t.encode_ms + t.encrypt_ms + t.eval_ms + t.decrypt_ms + t.decode_ms);
    }
    long double q_log2 = 0;
    for (const auto& limb : params->GetParams())
        q_log2 += std::log2(static_cast<long double>(limb->GetModulus().ConvertToInt()));
    std::cout << std::fixed << std::setprecision(6)
        << "{\"schema\":\"leveled-jet-comparison-v1\",\"status\":\"PASS\","
        << "\"scheme\":\"" << c.scheme << "\",\"layout\":\"" << c.layout
        << "\",\"schedule\":\"" << c.schedule << "\",\"length\":" << c.length
        << ",\"mults\":" << c.mults << ",\"jobs\":" << c.jobs
        << ",\"fixture_seed\":" << c.seed << ",\"fixture_fnv1a64\":\"" << fixture_hash
        << "\",\"fixture_generator\":\"std::mt19937_64 raw low bit; job-factor-coefficient order\""
        << ",\"input_distribution\":\"independent binary unit polynomials: constant 1, higher coefficients raw generator bits\""
        << ",\"crypto_randomness\":\"OpenFHE default fresh; fixture seed not supplied to cryptography\""
        << ",\"openfhe_version\":\"" << escape(GetOPENFHEVersion())
        << "\",\"compiler\":\"" << escape(__VERSION__)
        << "\",\"hardware_threads\":" << std::thread::hardware_concurrency()
        << ",\"omp_num_threads\":\"" << escape(std::getenv("OMP_NUM_THREADS") ? std::getenv("OMP_NUM_THREADS") : "unset")
        << "\",\"security_requested\":\"HEStd_128_classic\",\"independent_security_certification\":false"
        << ",\"security_scope\":\"OpenFHE automatic parameters for standard power-of-two ring; no ExactJet claim\""
        << ",\"plaintext_modulus\":" << (native ? 2 : packed_prime)
        << ",\"ring_dimension\":" << n << ",\"ciphertext_q_towers\":" << params->GetParams().size()
        << ",\"ciphertext_q_bits\":" << params->GetModulus().GetMSB()
        << ",\"ciphertext_q_log2\":" << static_cast<double>(q_log2)
        << ",\"key_switching_technique\":\"" << rns->GetKeySwitchTechnique()
        << "\",\"secret_key_distribution\":\"" << rns->GetSecretKeyDist()
        << "\",\"scaling_technique\":\"" << rns->GetScalingTechnique()
        << "\",\"encryption_technique\":\"" << rns->GetEncryptionTechnique()
        << "\",\"multiplication_technique\":\"" << rns->GetMultiplicationTechnique()
        << "\",\"key_switching_p_bits\":" << (rns->GetParamsP() ? rns->GetParamsP()->GetModulus().GetMSB() : 0)
        << ",\"key_switching_qp_bits\":" << (rns->GetParamsQP() ? rns->GetParamsQP()->GetModulus().GetMSB() : params->GetModulus().GetMSB())
        << ",\"key_switching_p_primes\":[";
    if (rns->GetParamsP()) for (std::size_t i = 0; i < rns->GetParamsP()->GetParams().size(); ++i) {
        if (i) std::cout << ',';
        std::cout << '"' << rns->GetParamsP()->GetParams()[i]->GetModulus() << '"';
    }
    std::cout << ']'
        << ",\"ciphertext_q_primes\":[";
    for (std::size_t i = 0; i < params->GetParams().size(); ++i) {
        if (i) std::cout << ',';
        std::cout << '"' << params->GetParams()[i]->GetModulus() << '"';
    }
    std::cout << "],\"output_q_towers\":" << output_towers
        << ",\"evaluation_points\":" << points << ",\"integer_low_coefficient_bound\":"
        << binomial(c.length - 1 + c.mults, c.mults)
        << ",\"jobs_per_ciphertext_capacity\":" << capacity << ",\"ciphertext_batches\":" << batches
        << ",\"input_ciphertexts\":" << batches * factors << ",\"output_ciphertexts\":" << batches
        << ",\"ctct_calls_per_trial\":" << batches * c.mults << ",\"ctct_depth\":" << depth
        << ",\"parameter_multiplicative_depth\":" << parameter_depth
        << ",\"parameter_depth_policy\":\"common sequential horizon mults for both schedules and both layouts\""
        << ",\"rotation_calls\":0,\"bootstrap_calls\":0,\"public_key_bytes\":" << public_key_bytes
        << ",\"relinearization_key_bytes\":" << relin_sink.bytes
        << ",\"input_bytes\":" << input_bytes << ",\"output_bytes\":" << output_bytes
        << ",\"serialization\":\"sum of separate OpenFHE binary object serializations; no compression\""
        << ",\"setup_ms\":" << setup_ms << ",\"precomputation_ms\":" << precomputation_ms
        << ",\"peak_rss_bytes\":" << peak_rss() << ",\"warmup_trials_excluded\":1"
        << ",\"repetitions\":" << c.repetitions
        << ",\"verified_output_coefficients_including_warmup\":" << c.jobs * c.length * (c.repetitions + 1)
        << ",\"correctness_scope\":\"every decrypted output in these finite trials; no failure-probability certification\""
        << ",\"median_ms\":{\"encode\":" << median(encode_times)
        << ",\"encrypt\":" << median(encrypt_times) << ",\"eval\":" << median(eval_times)
        << ",\"decrypt\":" << median(decrypt_times) << ",\"decode\":" << median(decode_times)
        << ",\"end_to_end\":" << median(end_to_end) << "},\"inputs\":[";
    for (std::size_t job = 0; job < inputs.size(); ++job) {
        if (job) std::cout << ',';
        std::cout << '[';
        for (std::size_t factor = 0; factor < inputs[job].size(); ++factor) {
            if (factor) std::cout << ',';
            print_polynomial(inputs[job][factor]);
        }
        std::cout << ']';
    }
    std::cout << "],\"trials\":[";
    for (std::size_t i = 0; i < trials.size(); ++i) {
        if (i) std::cout << ',';
        const auto& t = trials[i];
        std::cout << "{\"encode_ms\":" << t.encode_ms << ",\"encrypt_ms\":" << t.encrypt_ms
            << ",\"eval_ms\":" << t.eval_ms << ",\"decrypt_ms\":" << t.decrypt_ms
            << ",\"decode_ms\":" << t.decode_ms << ",\"decoded_outputs\":[";
        for (std::size_t job = 0; job < t.decoded_outputs.size(); ++job) {
            if (job) std::cout << ',';
            print_polynomial(t.decoded_outputs[job]);
        }
        std::cout << "]}";
    }
    std::cout << "]}\n";
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    try {
        const Config config = parse(argc, argv);
        if (config.self_test) { self_test(); return 0; }
        return run(config);
    } catch (const std::exception& error) {
        std::cout << "{\"status\":\"FAIL\",\"error\":\"" << escape(error.what()) << '"';
        if (failure.active) {
            std::cout << ",\"failure_context\":{\"scheme\":\"" << failure.config.scheme
                << "\",\"layout\":\"" << failure.config.layout
                << "\",\"schedule\":\"" << failure.config.schedule
                << "\",\"length\":" << failure.config.length
                << ",\"mults\":" << failure.config.mults << ",\"jobs\":" << failure.config.jobs
                << ",\"fixture_seed\":" << failure.config.seed
                << ",\"stage\":\"" << failure.stage << "\",\"trial_index_including_warmup\":" << failure.trial_index
                << ",\"warmup\":" << (failure.trial_index == 0 ? "true" : "false")
                << ",\"job_index\":" << failure.job_index << ",\"ring_dimension\":" << failure.ring_dimension
                << ",\"ciphertext_q_bits\":" << failure.q_bits
                << ",\"parameter_multiplicative_depth\":" << failure.parameter_depth
                << ",\"ctct_depth\":" << failure.actual_depth
                << ",\"decoded_coefficient_count\":" << failure.decoded_coefficient_count
                << ",\"actual\":";
            print_polynomial(failure.actual);
            std::cout << ",\"expected\":";
            print_polynomial(failure.expected);
            std::cout << '}';
        }
        std::cout << "}\n";
        return 1;
    }
}
