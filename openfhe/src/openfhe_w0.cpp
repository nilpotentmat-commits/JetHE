#include "exact_w0.h"
#include "pke/openfhe.h"
#include "pke/ciphertext-ser.h"
#include "pke/cryptocontext-ser.h"
#include "pke/key/key-ser.h"
#include "core/version.h"
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <streambuf>
#include <string>
#include <sched.h>
#include <sys/resource.h>

namespace {
using namespace exact_w0;
using namespace lbcrypto;
using Clock = std::chrono::steady_clock;
using Context = CryptoContext<DCRTPoly>;
using CT = Ciphertext<DCRTPoly>;
using Times = std::map<std::string, double>;
using Counts = std::map<std::string, uint64_t>;
double seconds(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now()-start).count();
}
struct Timer {
    Times& times; std::string key; Clock::time_point start = Clock::now();
    Timer(Times& t, std::string k) : times(t), key(std::move(k)) {}
    ~Timer() { times[key] += seconds(start); }
};
struct Config {
    std::string mode = "gate", arm = "summed-bsgs", scheme = "BFV";
    std::string bfv_key_switch = "BV";
    unsigned n = 16384, b = 32, jobs = 16, length = 256, batches = 1;
};
Config parse(int argc, char** argv) {
    Config c;
    for (int i = 1; i < argc; ++i) {
        const std::string option = argv[i];
        require(++i < argc, "missing CLI value");
        const std::string value = argv[i];
        if (option == "--mode") c.mode = value;
        else if (option == "--arm") c.arm = value;
        else if (option == "--scheme") c.scheme = value;
        else if (option == "--bfv-key-switch") c.bfv_key_switch = value;
        else {
            size_t consumed = 0;
            require(!value.empty() && value[0] != '-', "invalid unsigned CLI value");
            const unsigned long v = std::stoul(value, &consumed);
            require(consumed == value.size() && v <= 65536, "invalid numeric CLI value");
            if (option == "--ring-dim") c.n = v;
            else if (option == "--baby-width") c.b = v;
            else if (option == "--jobs") c.jobs = v;
            else if (option == "--length") c.length = v;
            else if (option == "--batches") c.batches = v;
            else throw std::runtime_error("unknown CLI option: " + option);
        }
    }
    require(c.mode == "clear" || c.mode == "gate" || c.mode == "sample", "invalid mode");
    require(c.arm == "summed-bsgs" || c.arm == "terminal-products" || c.arm == "recipient-compute", "invalid arm");
    require(c.scheme == "BFV" || c.scheme == "BGV", "invalid scheme");
    require(c.bfv_key_switch == "BV" || c.bfv_key_switch == "HYBRID", "invalid BFV key-switch choice");
    require(c.scheme == "BFV" || c.bfv_key_switch == "BV", "BFV key-switch option does not apply to BGV");
    require(c.n >= 1024 && c.n <= 32768 && !(c.n & (c.n-1)), "unsupported ring dimension");
    require(c.batches == 1 || c.batches == 2, "batches must be1or2");
    require(c.jobs && c.jobs <= 16 && c.length >= 2 && c.length <= 256 && !(c.length & (c.length-1)), "invalid fixture subset");
    if (c.arm == "summed-bsgs") {
        require(c.b >= 2 && c.b <= c.length && c.length % c.b == 0, "invalid BSGS width");
        Layout layout(c.n, c.length);
    }
    if (c.arm == "recipient-compute") require(2*c.jobs*c.length <= c.n, "boundary inputs do not fit");
    return c;
}
std::string quoted(const std::string& value) {
    std::ostringstream out; out << '"';
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c == '\n') out << "\\n";
        else if (c == '\r') out << "\\r";
        else if (c == '\t') out << "\\t";
        else if (c < 32) out << '?';
        else out << c;
    }
    out << '"'; return out.str();
}
template<class T> void print_vector(const std::vector<T>& v) {
    std::cout << '[';
    for (size_t i = 0; i < v.size(); ++i) { if (i) std::cout << ','; std::cout << v[i]; }
    std::cout << ']';
}
template<class T> void print_map(const std::map<std::string, T>& m) {
    std::cout << '{'; bool first = true;
    for (const auto& item : m) {
        if (!first) std::cout << ','; first = false;
        std::cout << quoted(item.first) << ':' << item.second;
    }
    std::cout << '}';
}
class CountingSink : public std::streambuf {
public: uint64_t bytes = 0;
protected:
    std::streamsize xsputn(const char*, std::streamsize n) override { bytes += n; return n; }
    int_type overflow(int_type c) override {
        if (!traits_type::eq_int_type(c, traits_type::eof())) ++bytes;
        return traits_type::not_eof(c);
    }
};
template<class T> uint64_t serialized_size(const T& value) {
    CountingSink sink; std::ostream stream(&sink);
    Serial::Serialize(value, stream, SerType::BINARY);
    require(bool(stream), "serialization failed"); return sink.bytes;
}
uint64_t peak_rss_kib() {
    rusage usage{}; require(getrusage(RUSAGE_SELF, &usage) == 0, "getrusage failed");
    return usage.ru_maxrss;
}
void assert_single_worker() {
    cpu_set_t affinity;CPU_ZERO(&affinity);
    require(sched_getaffinity(0,sizeof(affinity),&affinity)==0,"cannot read worker affinity");
    require(CPU_COUNT(&affinity)==1,"HE worker must be pinned to exactlyone CPU");
    const char* threads=std::getenv("OMP_NUM_THREADS");
    require(threads&&std::string(threads)=="1","OMP_NUM_THREADS must equal1");
}
bool bfv_summed(const Config& c) { return c.scheme == "BFV" && c.arm == "summed-bsgs"; }
unsigned circuit_depth(const Config& c) { return c.arm == "recipient-compute" ? 0 : 1; }
unsigned requested_depth(const Config& c) { return bfv_summed(c) ? 2 : circuit_depth(c); }
unsigned actual_additions(const Config& c) {
    return c.arm == "summed-bsgs" ? c.length-2 : (c.arm == "recipient-compute" ? 1 : 0);
}
unsigned requested_additions(const Config& c) { return bfv_summed(c) ? 0 : actual_additions(c); }
unsigned actual_key_switches(const Config& c) {
    return c.arm == "summed-bsgs" ? 1 + unsigned(c.length/c.b > 1) : 0;
}
unsigned requested_key_switches(const Config& c) {
    return bfv_summed(c) ? 0 : (c.arm == "summed-bsgs" ? 2 : 0);
}
template<class Parameters> void set_parameters(Parameters& p, const Config& c) {
    p.SetPlaintextModulus(prime);
    p.SetMultiplicativeDepth(requested_depth(c));
    p.SetSecurityLevel(HEStd_128_classic);
    p.SetRingDim(c.n);
    p.SetBatchSize(c.n);
    p.SetEvalAddCount(requested_additions(c));
    p.SetKeySwitchCount(requested_key_switches(c));
    if(c.scheme == "BFV")p.SetKeySwitchTechnique(c.bfv_key_switch == "HYBRID" ? HYBRID : BV);
}
Context make_context(const Config& c) {
    Context cc;
    if (c.scheme == "BFV") {
        CCParams<CryptoContextBFVRNS> p; set_parameters(p, c); cc = GenCryptoContext(p);
    } else {
        CCParams<CryptoContextBGVRNS> p; set_parameters(p, c); cc = GenCryptoContext(p);
    }
    cc->Enable(PKE); cc->Enable(LEVELEDSHE);
    if (c.arm == "summed-bsgs") cc->Enable(KEYSWITCH);
    require(cc->GetRingDimension() == c.n, "library changed requested ring dimension");
    return cc;
}
struct Batch {
    std::string state;
    Times times{{"owner_f",0},{"owner_g",0},{"codec",0},{"encryption",0},
                {"evaluation",0},{"serialization",0},{"decryption_codec",0},{"verification",0}};
    Counts inventory{{"ciphertext_products",0},{"ciphertext_additions",0},
                     {"relinearizations",0},{"rotations",0},{"bootstrap_calls",0}};
    uint64_t input_bytes = 0, output_bytes = 0, encryptions = 0, outputs = 0;
    unsigned output_components_min = 100, output_components_max = 0;
    unsigned output_towers_min = 100, output_towers_max = 0;
    double wall = 0;
    std::vector<uint16_t> recovered;
};
struct Runtime {
    const Config& c; const Context& cc; const KeyPair<DCRTPoly>& keys; Batch& result;
    CT encrypt(const std::vector<int64_t>& slots) {
        Plaintext plain;
        { Timer t(result.times, "codec"); plain = cc->MakePackedPlaintext(slots); }
        CT ciphertext;
        { Timer t(result.times, "encryption"); ciphertext = cc->Encrypt(keys.publicKey, plain); }
        require(ciphertext && ciphertext->GetElements().size() == 2, "encryption did not return2components");
        { Timer t(result.times, "serialization"); result.input_bytes += serialized_size(ciphertext); }
        ++result.encryptions; return ciphertext;
    }
    std::vector<int64_t> decrypt(const CT& ciphertext) {
        { Timer t(result.times, "serialization"); result.output_bytes += serialized_size(ciphertext); }
        ++result.outputs;
        const unsigned components = ciphertext->GetElements().size();
        const unsigned towers = ciphertext->GetElements()[0].GetNumOfElements();
        result.output_components_min = std::min(result.output_components_min, components);
        result.output_components_max = std::max(result.output_components_max, components);
        result.output_towers_min = std::min(result.output_towers_min, towers);
        result.output_towers_max = std::max(result.output_towers_max, towers);
        Timer t(result.times, "decryption_codec");
        Plaintext plain; auto status = cc->Decrypt(keys.secretKey, ciphertext, &plain);
        require(status.isValid, "library decryption rejected ciphertext");
        plain->SetLength(c.n);
        auto values = plain->GetPackedValue();
        require(values.size() == c.n, "decryption returned incomplete slot vector");
        return values;
    }
};

// This evaluator receives ciphertexts and public indices only. Owner f and g
// preparation is performed in separate loops below; no private joint preparation.
struct PublicBSGS {
    const Context& cc; const std::vector<CT>& babies; Counts& inventory;
    CT group, total;
    void consume(unsigned r, const CT& diagonal) {
        auto p = cc->EvalMultNoRelin(babies[r], diagonal);
        require(p->GetElements().size() == 3, "implicit relinearization of product");
        ++inventory["ciphertext_products"];
        if (group) { cc->EvalAddInPlace(group, p); ++inventory["ciphertext_additions"]; }
        else group = std::move(p);
    }
    void finish_group(int32_t rotation) {
        require(bool(group), "empty BSGS group");
        group = cc->Relinearize(group); ++inventory["relinearizations"];
        if (rotation) { group = cc->EvalRotate(group, rotation); ++inventory["rotations"]; }
        if (total) { cc->EvalAddInPlace(total, group); ++inventory["ciphertext_additions"]; }
        else total = group;
        group.reset();
    }
};

Batch summed_bsgs(const Config& c, const Inputs& in, const Codec& codec,
                  const Context& cc, const KeyPair<DCRTPoly>& keys) {
    Batch result; result.recovered.resize(c.jobs*c.length);
    const auto start = Clock::now(); Runtime run{c, cc, keys, result};
    const Layout layout(c.n, c.length);
    for (unsigned base = 0; base < c.jobs; base += layout.capacity) {
        const unsigned active = std::min(layout.capacity, c.jobs-base);
        std::vector<CT> babies; babies.reserve(c.b);
        for (unsigned r = 0; r < c.b; ++r) {
            std::vector<int64_t> slots;
            { Timer t(result.times, "owner_f"); slots.assign(c.n, 0);
                for (unsigned q = 0; q < active; ++q) for (unsigned k = 0; k < c.length; ++k) {
                    const auto& values = codec.values[in.f[base+q][(k+r)%c.length]];
                    for (unsigned s = 0; s < points; ++s) slots[layout.slot(q,k,s)] = values[s];
                }
            }
            babies.push_back(run.encrypt(slots));
        }
        std::vector<Powers> columns;
        { Timer t(result.times, "owner_g");
            for (unsigned q = 0; q < active; ++q) columns.push_back(powers(in.g[base+q]));
        }
        PublicBSGS evaluator{cc, babies, result.inventory, {}, {}};
        for (unsigned h = 0; h < c.length; h += c.b) {
            for (unsigned r = 0; r < c.b; ++r) {
                if (h+r == 1) continue; // identicallyzero becauseg[0]=0.
                std::vector<int64_t> slots;
                { Timer t(result.times, "owner_g"); slots.assign(c.n, 0);
                    for (unsigned q = 0; q < active; ++q) for (unsigned k = 0; k < c.length; ++k) {
                        const unsigned i = (k+r)%c.length, y = (k+c.length-h)%c.length;
                        const auto& values = codec.values[columns[q][i][y]];
                        for (unsigned s = 0; s < points; ++s) slots[layout.slot(q,k,s)] = values[s];
                    }
                }
                auto diagonal = run.encrypt(slots);
                { Timer t(result.times, "evaluation"); evaluator.consume(r, diagonal); }
            }
            { Timer t(result.times, "evaluation"); evaluator.finish_group(layout.rotation(h)); }
        }
        auto decoded = run.decrypt(evaluator.total);
        { Timer t(result.times, "decryption_codec");
            for (unsigned q = 0; q < active; ++q) for (unsigned k = 0; k < c.length; ++k) {
                std::array<uint32_t, points> values{};
                for (unsigned s = 0; s < points; ++s) values[s] = canonical(decoded[layout.slot(q,k,s)]);
                result.recovered[(base+q)*c.length+k] = codec.recover(values,16*c.length);
            }
        }
    }
    const unsigned bundles = (c.jobs+layout.capacity-1)/layout.capacity;
    require(result.encryptions == uint64_t(bundles)*(c.length-1+c.b), "BSGS input inventory mismatch");
    require(result.inventory["ciphertext_products"] == uint64_t(bundles)*(c.length-1), "BSGS product inventory mismatch");
    require(result.inventory["relinearizations"] == uint64_t(bundles)*(c.length/c.b), "BSGS relin inventory mismatch");
    require(result.inventory["rotations"] == uint64_t(bundles)*(c.length/c.b-1), "BSGS rotation inventory mismatch");
    result.wall = seconds(start); return result;
}

struct Record { uint16_t job, power, coefficient; };
std::vector<Record> make_records(const Config& c) {
    std::vector<Record> rows; rows.reserve(c.jobs*c.length*(c.length-1)/2);
    for (unsigned j = 0; j < c.jobs; ++j)
        for (unsigned k = 1; k < c.length; ++k)
            for (unsigned i = 1; i <= k; ++i) rows.push_back({uint16_t(j),uint16_t(i),uint16_t(k)});
    return rows;
}
Batch terminal_products(const Config& c, const Inputs& in, const Codec& codec,
        const std::vector<Record>& rows, const Context& cc, const KeyPair<DCRTPoly>& keys) {
    Batch result; result.recovered.resize(c.jobs*c.length);
    const auto start = Clock::now(); Runtime run{c, cc, keys, result};
    // The constant term is sent separately as16-bit integers. Its ciphertext is
    // forwarded unchanged and both transmissions plus decryption are charged.
    std::vector<int64_t> constants;
    { Timer t(result.times, "owner_f"); constants.assign(c.n,0);
        for (unsigned j = 0; j < c.jobs; ++j) constants[j] = in.f[j][0]; }
    auto constant_ciphertext = run.encrypt(constants);
    auto constant_values = run.decrypt(constant_ciphertext);
    { Timer t(result.times, "decryption_codec");
        for (unsigned j = 0; j < c.jobs; ++j) {
            const auto value = canonical(constant_values[j]); require(value < 65536,"invalid constant term");
            result.recovered[j*c.length] = uint16_t(value);
        }
    }
    std::vector<Powers> columns;
    { Timer t(result.times, "owner_g");
        for (unsigned j = 0; j < c.jobs; ++j) columns.push_back(powers(in.g[j])); }
    std::vector<std::array<uint32_t,points>> accumulated(c.jobs*c.length);
    const unsigned records_per_ciphertext = c.n/points;
    for (size_t base = 0; base < rows.size(); base += records_per_ciphertext) {
        const unsigned active = std::min<size_t>(records_per_ciphertext,rows.size()-base);
        std::vector<int64_t> left, right;
        { Timer t(result.times,"owner_f"); left.assign(c.n,0);
            for (unsigned a = 0; a < active; ++a) {
                const auto row = rows[base+a]; const auto& v = codec.values[in.f[row.job][row.power]];
                for (unsigned s = 0; s < points; ++s) left[a*points+s] = v[s];
            }
        }
        { Timer t(result.times,"owner_g"); right.assign(c.n,0);
            for (unsigned a = 0; a < active; ++a) {
                const auto row = rows[base+a]; const auto& v = codec.values[columns[row.job][row.power][row.coefficient]];
                for (unsigned s = 0; s < points; ++s) right[a*points+s] = v[s];
            }
        }
        auto f = run.encrypt(left), g = run.encrypt(right); CT output;
        { Timer t(result.times,"evaluation"); output = cc->EvalMultNoRelin(f,g);
            require(output->GetElements().size() == 3,"terminal product was relinearized");
            ++result.inventory["ciphertext_products"]; }
        auto decoded = run.decrypt(output);
        { Timer t(result.times,"decryption_codec");
            for (unsigned a = 0; a < active; ++a) {
                const auto row = rows[base+a]; auto& sum = accumulated[row.job*c.length+row.coefficient];
                for (unsigned s = 0; s < points; ++s)
                    sum[s] = (sum[s] + canonical(decoded[a*points+s])) % prime;
            }
        }
    }
    { Timer t(result.times,"decryption_codec");
        for (unsigned j = 0; j < c.jobs; ++j) for (unsigned k = 1; k < c.length; ++k)
            result.recovered[j*c.length+k] = codec.recover(accumulated[j*c.length+k],16*c.length);
    }
    const size_t products = (rows.size()+records_per_ciphertext-1)/records_per_ciphertext;
    require(result.encryptions == 2*products+1 && result.outputs == products+1,"terminal inventory mismatch");
    result.wall = seconds(start); return result;
}
Batch recipient_compute(const Config& c, const Inputs& in, const Context& cc,
                        const KeyPair<DCRTPoly>& keys) {
    Batch result; result.recovered.resize(c.jobs*c.length);
    const auto start = Clock::now(); Runtime run{c,cc,keys,result};
    const unsigned offset = c.jobs*c.length;
    std::vector<int64_t> left, right;
    { Timer t(result.times,"owner_f"); left.assign(c.n,0);
        for (unsigned j=0;j<c.jobs;++j) for(unsigned k=0;k<c.length;++k) left[j*c.length+k]=in.f[j][k]; }
    { Timer t(result.times,"owner_g"); right.assign(c.n,0);
        for (unsigned j=0;j<c.jobs;++j) for(unsigned k=0;k<c.length;++k) right[offset+j*c.length+k]=in.g[j][k]; }
    auto f=run.encrypt(left),g=run.encrypt(right); CT output;
    { Timer t(result.times,"evaluation"); output=cc->EvalAdd(f,g); ++result.inventory["ciphertext_additions"]; }
    auto decoded=run.decrypt(output);
    { Timer t(result.times,"decryption_codec");
        for(unsigned j=0;j<c.jobs;++j) {
            Jet plain_f(c.length),plain_g(c.length);
            for(unsigned k=0;k<c.length;++k) {
                const auto a=canonical(decoded[j*c.length+k]),b=canonical(decoded[offset+j*c.length+k]);
                require(a<65536&&b<65536,"boundary input not16bit");
                plain_f[k]=uint16_t(a);plain_g[k]=uint16_t(b);
            }
            auto value=horner(plain_f,plain_g);
            std::copy(value.begin(),value.end(),result.recovered.begin()+j*c.length);
        }
    }
    result.wall=seconds(start);return result;
}

std::vector<uint16_t> clear_bsgs(const Config& c, const Inputs& in, const Codec& codec) {
    const Layout layout(c.n,c.length); std::vector<uint16_t> recovered(c.jobs*c.length);
    for(unsigned base=0;base<c.jobs;base+=layout.capacity) {
        const unsigned active=std::min(layout.capacity,c.jobs-base);
        std::vector<Powers> columns;
        for(unsigned q=0;q<active;++q)columns.push_back(powers(in.g[base+q]));
        std::vector<uint32_t> total(c.n);
        for(unsigned h=0;h<c.length;h+=c.b) {
            std::vector<uint32_t> group(c.n);
            for(unsigned r=0;r<c.b;++r) {
                if(h+r==1)continue;
                for(unsigned q=0;q<active;++q)for(unsigned k=0;k<c.length;++k) {
                    const unsigned i=(k+r)%c.length,y=(k+c.length-h)%c.length;
                    const auto& a=codec.values[in.f[base+q][i]];
                    const auto& b=codec.values[columns[q][i][y]];
                    for(unsigned s=0;s<points;++s) {
                        auto& v=group[layout.slot(q,k,s)];v=(v+uint64_t(a[s])*b[s])%prime;
                    }
                }
            }
            // Simulate the actual two-row physical permutation, not a presumed
            // per-job mathematical rotation. This detects cross-job leakage.
            for(unsigned half=0;half<2;++half)for(unsigned slot=0;slot<c.n/2;++slot) {
                const unsigned target=half*(c.n/2)+slot;
                const unsigned source=half*(c.n/2)+(slot+layout.rotation(h))%(c.n/2);
                total[target]=(total[target]+group[source])%prime;
            }
        }
        for(unsigned q=0;q<active;++q)for(unsigned k=0;k<c.length;++k) {
            std::array<uint32_t,points> values{};
            for(unsigned s=0;s<points;++s)values[s]=total[layout.slot(q,k,s)];
            recovered[(base+q)*c.length+k]=codec.recover(values,16*c.length);
        }
    }
    return recovered;
}
std::vector<uint16_t> clear_terminal(const Config& c,const Inputs& in,const Codec& codec,
                                   const std::vector<Record>& rows) {
    std::vector<Powers> columns;for(unsigned j=0;j<c.jobs;++j)columns.push_back(powers(in.g[j]));
    std::vector<std::array<uint32_t,points>> accumulated(c.jobs*c.length);
    for(const auto row:rows) {
        const auto& a=codec.values[in.f[row.job][row.power]];
        const auto& b=codec.values[columns[row.job][row.power][row.coefficient]];
        auto& sum=accumulated[row.job*c.length+row.coefficient];
        for(unsigned s=0;s<points;++s)sum[s]=(sum[s]+uint64_t(a[s])*b[s])%prime;
    }
    std::vector<uint16_t> out(c.jobs*c.length);
    for(unsigned j=0;j<c.jobs;++j)for(unsigned k=0;k<c.length;++k)
        out[j*c.length+k]=k?codec.recover(accumulated[j*c.length+k],16*c.length):in.f[j][0];
    return out;
}
std::vector<uint16_t> clear_recipient(const Config& c,const Inputs& in) {
    const unsigned offset=c.jobs*c.length;
    std::vector<uint32_t> left(c.n),right(c.n);
    for(unsigned j=0;j<c.jobs;++j)for(unsigned k=0;k<c.length;++k) {
        left[j*c.length+k]=in.f[j][k];right[offset+j*c.length+k]=in.g[j][k];
    }
    for(unsigned s=0;s<c.n;++s)left[s]=(left[s]+right[s])%prime;
    std::vector<uint16_t> out;
    for(unsigned j=0;j<c.jobs;++j) {
        Jet f(c.length),g(c.length);
        for(unsigned k=0;k<c.length;++k) {
            require(left[j*c.length+k]<65536&&left[offset+j*c.length+k]<65536,"invalid clear boundary input");
            f[k]=left[j*c.length+k];g[k]=left[offset+j*c.length+k];
        }
        auto value=horner(f,g);out.insert(out.end(),value.begin(),value.end());
    }
    return out;
}
void verify(Batch& batch,const std::vector<uint16_t>& expected) {
    Timer t(batch.times,"verification");require(batch.recovered==expected,"full output/Horner mismatch");
}
void print_batch(const Batch& b) {
    std::cout<<"{\"state\":"<<quoted(b.state)<<",\"coldwarm\":"<<quoted(b.state)
        <<",\"status\":\"PASS\",\"batch_wall_seconds\":"<<b.wall<<",\"seconds\":";
    print_map(b.times);std::cout<<",\"input_bytes_serialized\":"<<b.input_bytes
        <<",\"output_bytes_serialized\":"<<b.output_bytes<<",\"fresh_encryptions\":"<<b.encryptions
        <<",\"returned_ciphertexts\":"<<b.outputs<<",\"executed_inventory\":";print_map(b.inventory);
    std::cout<<",\"output_components_min\":"<<b.output_components_min<<",\"output_components_max\":"<<b.output_components_max
        <<",\"output_q_towers_min\":"<<b.output_towers_min<<",\"output_q_towers_max\":"<<b.output_towers_max
        <<",\"recovered_symbols\":";print_vector(b.recovered);std::cout<<'}';
}
void print_profile(const Config& c,const Context& cc,const KeyPair<DCRTPoly>& keys) {
    const auto params=cc->GetCryptoParameters()->GetElementParams();
    const auto rns=std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    require(bool(rns),"missing RNS parameters");
    std::cout<<"{\"scheme\":"<<quoted(c.scheme)<<",\"arm\":"<<quoted(c.arm)<<",\"ring_dimension\":"<<c.n
        <<",\"plaintext_modulus\":"<<prime<<",\"field_polynomial\":\"0x1100b\",\"field_degree\":16"
        <<",\"length\":"<<c.length<<",\"jobs\":"<<c.jobs<<",\"baby_width\":"<<c.b<<",\"evaluation_points\":32"
        <<",\"integer_lift_coefficient_bound\":"<<16*c.length<<",\"requested_multiplicative_depth\":"<<requested_depth(c)
        <<",\"requested_eval_add_count\":"<<requested_additions(c)<<",\"requested_key_switch_count\":"<<requested_key_switches(c)
        <<",\"actual_circuit_multiplicative_depth\":"<<circuit_depth(c)
        <<",\"actual_additions_per_output_ciphertext\":"<<actual_additions(c)
        <<",\"actual_max_key_switches_per_product_path\":"<<actual_key_switches(c)
        <<",\"bfv_key_switch_requested\":"<<quoted(c.scheme=="BFV"?c.bfv_key_switch:"not-applicable")
        <<",\"parameter_sizing_policy\":"<<quoted(bfv_summed(c)?"BFV multiplication-only sizing depth2; actual depth1 plus charged accumulation and key switches":"unchanged v1 parameter policy")
        <<",\"security_requested\":\"HEStd_128_classic\",\"security_certified\":false,\"security_matched_to_JetHE\":false"
        <<",\"openfhe_version\":"<<quoted(GetOPENFHEVersion())<<",\"openfhe_source_commit\":\"1306d14f8c26bb6150d3e6ad54f28dfe1007689e\""
        <<",\"compiler\":"<<quoted(__VERSION__)<<",\"ciphertext_q_bits\":"<<params->GetModulus().GetMSB()
        <<",\"ciphertext_q_decimal\":"<<quoted(params->GetModulus().ToString())<<",\"ciphertext_q_primes\":[";
    for(unsigned i=0;i<params->GetParams().size();++i){if(i)std::cout<<',';std::cout<<quoted(params->GetParams()[i]->GetModulus().ToString());}
    std::cout<<"],\"key_switching_p_bits\":"<<(rns->GetParamsP()?rns->GetParamsP()->GetModulus().GetMSB():0)
        <<",\"key_switching_qp_bits\":"<<(rns->GetParamsQP()?rns->GetParamsQP()->GetModulus().GetMSB():params->GetModulus().GetMSB())
        <<",\"key_switching_p_primes\":[";
    if(rns->GetParamsP())for(unsigned i=0;i<rns->GetParamsP()->GetParams().size();++i){if(i)std::cout<<',';std::cout<<quoted(rns->GetParamsP()->GetParams()[i]->GetModulus().ToString());}
    std::ostringstream sk,ks,scale,enc,mult;
    sk<<rns->GetSecretKeyDist();ks<<rns->GetKeySwitchTechnique();scale<<rns->GetScalingTechnique();enc<<rns->GetEncryptionTechnique();mult<<rns->GetMultiplicationTechnique();
    std::cout<<"],\"secret_key_distribution\":"<<quoted(sk.str())<<",\"error_stddev\":"<<rns->GetDistributionParameter()
        <<",\"key_switching_technique\":"<<quoted(ks.str())<<",\"scaling_technique\":"<<quoted(scale.str())
        <<",\"encryption_technique\":"<<quoted(enc.str())<<",\"multiplication_technique\":"<<quoted(mult.str())
        <<",\"generated_relinearization_keys\":"<<(c.arm=="summed-bsgs"?1:0)
        <<",\"generated_rotation_keys\":"<<(c.arm=="summed-bsgs"&&c.length/c.b>1?cc->GetEvalAutomorphismKeyMap(keys.secretKey->GetKeyTag()).size():0)<<'}';
}
int run(int argc,char** argv) {
    const Config c=parse(argc,argv);const Inputs in=inputs(c.jobs,c.length);
    if(c.mode!="clear")assert_single_worker();
    std::cerr<<"Preparing independent Horner reference for"<<c.jobs<<" jobs of length"<<c.length<<"\n";
    const auto verification_start=Clock::now();std::vector<uint16_t> expected;
    for(unsigned j=0;j<c.jobs;++j){auto value=horner(in.f[j],in.g[j]);expected.insert(expected.end(),value.begin(),value.end());}
    const double reference_seconds=seconds(verification_start);
    Times setup;const auto setup_start=Clock::now();
    std::unique_ptr<Codec> codec;std::vector<Record> rows;
    {Timer t(setup,"public_precomputation");
        if(c.arm!="recipient-compute")codec=std::make_unique<Codec>();
        if(c.arm=="terminal-products")rows=make_records(c);}
    std::cout<<std::fixed<<std::setprecision(9);
    if(c.mode=="clear") {
        const auto start=Clock::now();std::vector<uint16_t> actual;
        if(c.arm=="summed-bsgs")actual=clear_bsgs(c,in,*codec);
        else if(c.arm=="terminal-products")actual=clear_terminal(c,in,*codec,rows);
        else actual=clear_recipient(c,in);
        require(actual==expected,"clear adapter/Horner mismatch");
        std::cout<<"{\"schema\":\"openfhe-matched-w0-v2\",\"status\":\"PASS\",\"mode\":\"clear\",\"arm\":"<<quoted(c.arm)
            <<",\"encrypted_execution\":false,\"security_certified\":false,\"ring_dimension\":"<<c.n<<",\"baby_width\":"<<c.b
            <<",\"jobs\":"<<c.jobs<<",\"length\":"<<c.length<<",\"fixture_fnv1a64\":"<<quoted(std::to_string(in.full_fixture_checksum))
            <<",\"clear_seconds\":"<<seconds(start)<<",\"reference_seconds\":"<<reference_seconds<<",\"recovered_symbols\":";
        print_vector(actual);std::cout<<"}\n";return 0;
    }
    Context cc;{Timer t(setup,"context");cc=make_context(c);}
    KeyPair<DCRTPoly> keys;
    {Timer t(setup,"keys");keys=cc->KeyGen();require(keys.good(),"key generation failed");
        if(c.arm=="summed-bsgs") {
            cc->EvalMultKeyGen(keys.secretKey);const Layout layout(c.n,c.length);std::vector<int32_t> rotations;
            for(unsigned h=c.b;h<c.length;h+=c.b)rotations.push_back(layout.rotation(h));
            if(!rotations.empty())cc->EvalRotateKeyGen(keys.secretKey,rotations);
        }
    }
    uint64_t public_key_bytes=0,mult_bytes=0,rotation_bytes=0,context_bytes=0;
    {Timer t(setup,"serialization");context_bytes=serialized_size(cc);public_key_bytes=serialized_size(keys.publicKey);
        if(c.arm=="summed-bsgs") {
            CountingSink mult_sink;std::ostream mult_stream(&mult_sink);
            require(cc->SerializeEvalMultKey(mult_stream,SerType::BINARY,keys.secretKey->GetKeyTag()),"eval mult key serialization failed");
            mult_bytes=mult_sink.bytes;
            if(c.length/c.b>1){CountingSink rotation_sink;std::ostream rotation_stream(&rotation_sink);
                require(cc->SerializeEvalAutomorphismKey(rotation_stream,SerType::BINARY,keys.secretKey->GetKeyTag()),"rotation key serialization failed");
                rotation_bytes=rotation_sink.bytes;}
        }
    }
    const double setup_wall=seconds(setup_start);std::vector<Batch> batches;
    for(unsigned trial=0;trial<c.batches;++trial) {
        std::cerr<<"Starting"<<(trial?" warm":" cold")<<" batch for "<<c.arm<<" "<<c.scheme<<" N="<<c.n<<"\n";
        Batch batch;
        if(c.arm=="summed-bsgs")batch=summed_bsgs(c,in,*codec,cc,keys);
        else if(c.arm=="terminal-products")batch=terminal_products(c,in,*codec,rows,cc,keys);
        else batch=recipient_compute(c,in,cc,keys);
        batch.state=trial?"warm":"cold";verify(batch,expected);batches.push_back(std::move(batch));
    }
    std::cout<<"{\"schema\":\"openfhe-matched-w0-v2\",\"status\":\"PASS\",\"mode\":"<<quoted(c.mode)
        <<",\"encrypted_execution\":true,\"security_certified\":false,\"matched_jobs\":"<<c.jobs<<",\"length\":"<<c.length
        <<",\"worker_threads\":1,\"fixture_fnv1a64\":"<<quoted(std::to_string(in.full_fixture_checksum))
        <<",\"fixture_scope\":"<<quoted(c.jobs==16&&c.length==256?"current-W0-full":"explicit-small-fixture-subset")
        <<",\"crypto_randomness\":\"OpenFHE fresh default; public fixture seed never supplied to encryption\""
        <<",\"recipient_disclosure\":"<<quoted(c.arm=="recipient-compute"?"complete f and g inputs":c.arm=="terminal-products"?"individual bit-polynomial product evaluations and f0":"aggregate bit-polynomial product evaluations")
        <<",\"work_placement_boundary\":"<<(c.arm=="recipient-compute"?"true":"false")
        <<",\"timing_scope\":\"all owner preparation, encode, encrypt, evaluator, separate binary serializations, decrypt and required recipient computation; excludes reference and correctness verification, network, process startup\""
        <<",\"serialization_method\":\"counting sink for independent OpenFHE binary object archives; no payload or secret keys retained\""
        <<",\"profile\":";print_profile(c,cc,keys);
    std::cout<<",\"setup_seconds\":";print_map(setup);
    std::cout<<",\"setup_wall_seconds\":"<<setup_wall<<",\"reference_verification_seconds\":"<<reference_seconds
        <<",\"public_key_bytes_serialized\":"<<public_key_bytes<<",\"relinearization_key_bytes_serialized\":"<<mult_bytes
        <<",\"rotation_key_bytes_serialized\":"<<rotation_bytes
        <<",\"public_key_including_hints_bytes_serialized\":"<<public_key_bytes+mult_bytes+rotation_bytes
        <<",\"context_bytes_serialized\":"<<context_bytes
        <<",\"public_material_including_context_bytes_serialized\":"<<public_key_bytes+mult_bytes+rotation_bytes+context_bytes
        <<",\"peak_rss_kib\":"<<peak_rss_kib()<<",\"batches\":[";
    for(unsigned i=0;i<batches.size();++i){if(i)std::cout<<',';print_batch(batches[i]);}
    std::cout<<"]}\n";return 0;
}
} // namespace
int main(int argc,char** argv) {
    try{return run(argc,argv);}
    catch(const std::exception& e){
        std::cerr<<"FAIL: "<<e.what()<<'\n';
        std::cout<<"{\"schema\":\"openfhe-matched-w0-v2\",\"status\":\"FAIL\",\"error\":"<<quoted(e.what())<<"}\n";
        return 1;
    }
}
