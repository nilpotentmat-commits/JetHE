// Actual-public-modulus screen correction. The original terminal_core.cpp is retained.
// Build and run only through the bounded, source-bound core supervisor.
#include "core_math.h"
#include <helib/helib.h>
#include <helib/JsonWrapper.h>
#include <NTL/BasicThreadPool.h>
#include <NTL/GF2X.h>
#include <json.hpp>
#include <any>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <streambuf>
#include <sys/resource.h>
#include <typeinfo>

using core::require;
using core::Words;
using Json=nlohmann::json;
using Clock=std::chrono::steady_clock;
using Times=std::map<std::string,double>;
struct Timer {
  Times* times; std::string name; Clock::time_point start;
  Timer(Times* t,std::string n):times(t),name(std::move(n)) { if(times) start=Clock::now(); }
  ~Timer() { if(times) (*times)[name]+=std::chrono::duration<double>(Clock::now()-start).count(); }
};
struct CountBuffer:std::streambuf {
  uint64_t bytes=0;
  std::streamsize xsputn(const char*,std::streamsize n) override { bytes+=uint64_t(n); return n; }
  int overflow(int c) override { if(c!=traits_type::eof()) ++bytes; return traits_type::not_eof(c); }
};
template<class T> uint64_t serialized_size(const T& value) {
  CountBuffer buf; std::ostream stream(&buf); value.writeTo(stream);
  require(bool(stream),"Serialization failed"); return buf.bytes;
}
static NTL::ZZX polynomial(uint16_t x) {
  NTL::ZZX p;
  for(unsigned i=0;i<16;++i) if((x>>i)&1) NTL::SetCoeff(p,i,1);
  return p;
}
static uint16_t symbol(const NTL::ZZX& p) {
  require(NTL::deg(p)<16,"Non-field output"); unsigned out=0;
  for(long i=0;i<=NTL::deg(p);++i) {
    require(NTL::coeff(p,i)==0||NTL::coeff(p,i)==1,"Nonbinary field coefficient");
    if(NTL::IsOne(NTL::coeff(p,i))) out|=1u<<i;
  }
  return uint16_t(out);
}
static std::vector<long> indices(const helib::IndexSet& set) {
  std::vector<long> out; for(long i:set) out.push_back(i); return out;
}
static std::vector<std::string> primes(const helib::Context& c,const helib::IndexSet& set) {
  std::vector<std::string> out;
  for(long i:set) out.push_back(std::to_string(c.ithPrime(i)));
  return out;
}
static std::vector<std::array<long,3>> handles(const helib::Ctxt& c) {
  // HElib has no public part-count getter. This allocates a complete temporary
  // JSON DOM; call only at declared functional checkpoints, never time as Eval.
  auto wrapper=c.writeToJSON();
  const auto& json=std::any_cast<const Json&>(wrapper.getJSONobj());
  std::vector<std::array<long,3>> out;
  for(const auto& part:json.at("content").at("parts")) {
    const auto& h=part.at("skHandle");
    out.push_back({h.at("powerOfS").get<long>(),h.at("powerOfX").get<long>(),h.at("secretKeyID").get<long>()});
  }
  return out;
}
static void check_handles(const std::vector<std::array<long,3>>& h,unsigned parts) {
  require(h.size()==parts,"Wrong actual raw component count"); std::set<long> powers;
  for(const auto& x:h) {
    require(x[0]>=0&&x[0]<long(parts),"Unexpected secret power");
    if(x[0]) require(x[1]==1&&x[2]==0,"Unexpected component key/automorphism");
    require(powers.insert(x[0]).second,"Duplicate secret power");
  }
}
struct Policy {
  std::string name; bool first=false,second=false;
  unsigned matrices=0,terminal_parts=3,products_per_group=4;
};
static Policy policy(const core::Cell& c,const std::string& arm,const std::string& name) {
  if(arm=="b16") { require(name=="raw"&&c.name=="w1-l256-j16","Wrong BSGS anchor"); return {name,false,false,16,3,1024}; }
  require(arm=="crt","Unknown compiler");
  if(c.family!=3) { require(name=="raw","Non-deep policy"); return {name,false,false,0,3,4}; }
  if(name=="yy") return {name,true,true,1,3,28};
  if(name=="yn") return {name,true,false,1,5,33};
  if(name=="ny") return {name,false,true,3,3,38};
  require(name=="nn","Unknown deep policy"); return {name,false,false,0,9,59};
}
static Json profile(const helib::Context& c,const helib::EncryptedArray& ea,long bits,const std::string& arm) {
  Json digits=Json::array();
  for(const auto& d:c.getDigits()) { require(d.card()>0,"Empty gadget digit"); digits.push_back(indices(d)); }
  std::vector<long> gens,ords;
  for(long i=0;i<c.getZMStar().numOfGens();++i) { gens.push_back(c.getZMStar().ZmStarGen(i)); ords.push_back(c.getZMStar().OrderOf(i)); }
  return {{"m",c.getM()},{"dimension",c.getPhiM()},{"slots",ea.size()},{"field_degree",ea.getDegree()},
    {"field_polynomial","0x1100b"},{"requested_bits",bits},{"requested_digits",2},
    {"actual_digit_prime_indices",digits},{"sk_hwt",0},{"generators",gens},{"orders",ords},
    {"compiler",arm},{"ciphertext_primes",primes(c,c.getCtxtPrimes())},
    {"special_primes",primes(c,c.getSpecialPrimes())},{"small_primes",primes(c,c.getSmallPrimes())},
    {"library_security_estimate_NOT_CERTIFICATION",c.securityLevel()},
    {"library_128_screen",c.securityLevel()>=128},{"security_128_qualified",false}};
}
static void entropy_seed() {
  std::array<unsigned char,32> bytes{};
  std::ifstream source("/dev/urandom",std::ios::binary);
  require(bool(source.read(reinterpret_cast<char*>(bytes.data()),bytes.size())),"OS entropy unavailable");
  NTL::SetSeed(NTL::ZZFromBytes(bytes.data(),bytes.size())); bytes.fill(0);
}
static unsigned slot(unsigned job,unsigned j) { return 32*(j/16)+16*job+j%16; }

static Json public_carrier(const helib::Context& c,const helib::EncryptedArray& ea,const std::string& arm) {
  require(ea.getDegree()==16&&c.getOrdP()==16&&ea.size()*16==c.getPhiM(),"Incorrect extension carrier");
  core::Field field; uint64_t seed=0x4352545055424c49ULL;
  std::vector<NTL::ZZX> a(ea.size()),b(ea.size()),expected(ea.size()),decoded;
  for(long i=0;i<ea.size();++i) {
    const auto x=core::draw(seed),y=core::draw(seed);
    a[i]=polynomial(x); b[i]=polynomial(y); expected[i]=polynomial(core::slow_mul(x,y));
  }
  NTL::ZZX pa,pb; ea.encode(pa,a); ea.encode(pb,b);
  ea.decode(decoded,pa); require(decoded==a,"Carrier first roundtrip");
  ea.decode(decoded,pb); require(decoded==b,"Carrier second roundtrip");
  NTL::GF2X phi,ga,gb,gp; NTL::conv(phi,c.getZMStar().getPhimX()); NTL::conv(ga,pa); NTL::conv(gb,pb);
  NTL::GF2XModulus modulus(phi); NTL::MulMod(gp,ga,gb,modulus);
  NTL::ZZX pp; NTL::conv(pp,gp); ea.decode(decoded,pp); require(decoded==expected,"Carrier full-field product");
  if(arm=="b16") {
    const auto& z=c.getZMStar();
    require(c.getM()==13107&&z.numOfGens()==2&&z.OrderOf(0)==16&&z.OrderOf(1)==32&&z.SameOrd(0),"Wrong BSGS axes");
    require(z.ZmStarGen(0)==4627&&z.ZmStarGen(1)==12853,"Wrong BSGS generators");
    std::set<long> units;
    for(unsigned q=0;q<2;++q) for(unsigned j=0;j<256;++j) {
      const long pos=slot(q,j); require(z.coordinate(0,pos)==long(j/16)&&z.coordinate(1,pos)==long(16*q+j%16),"BSGS position");
      long rep=NTL::MulMod(NTL::PowerMod(4627,j/16,13107),NTL::PowerMod(12853,16*q+j%16,13107),13107);
      require(rep==z.ith_rep(pos),"BSGS representative");
      for(unsigned f=0;f<16;++f) { require(units.insert(rep).second,"BSGS duplicate coset"); rep=NTL::MulMod(rep,2,13107); }
    }
    require(units.size()==8192,"BSGS incomplete unit cover");
    for(unsigned v=1;v<16;++v) {
      NTL::GF2X xk,mapped; NTL::PowerXMod(xk,z.genToPow(0,-long(v)),modulus); NTL::CompMod(mapped,ga,xk,modulus);
      NTL::conv(pp,mapped); ea.decode(decoded,pp);
      for(unsigned q=0;q<2;++q) for(unsigned j=0;j<256;++j)
        require(decoded[slot(q,j)]==a[slot(q,(j+16*v)%256)],"BSGS full-field substitution");
    }
  }
  return {{"roundtrips",2},{"field_products_checked",ea.size()},{"polynomial_automorphisms_checked",arm=="b16"?15:0}};
}

struct Ledger {
  uint64_t encryptions=0,products=0,component_products=0,adds=0,relins=0,switched_parts=0,rotations=0,explicit_mod_changes=0;
  uint64_t input_bytes=0,output_bytes=0;
  unsigned handle_checkpoints=0;
  Json checkpoints=Json::array();
  double min_capacity=1e300; bool all_library_correct=true;
  Times times;
  Json json() const { return {{"encryptions",encryptions},{"products",products},{"component_products",component_products},
    {"additions",adds},{"relinearizations",relins},{"switched_parts",switched_parts},{"rotations",rotations},
    {"explicit_modulus_changes",explicit_mod_changes},{"input_bytes_serialized",input_bytes},
    {"output_bytes_serialized",output_bytes},{"structural_handle_checkpoints",handle_checkpoints},
    {"minimum_observed_bit_capacity",min_capacity},{"all_observed_library_correct",all_library_correct},
    {"checkpoints",checkpoints}}; }
};
// Evaluators receive only encrypted operands/public context. The harness below
// holds owner inputs and the recipient key, but this is NOT process isolation.
class Evaluator {
  const helib::Context& context; Ledger& ledger; Times* times; bool gate;
public:
  Evaluator(const helib::Context& c,Ledger& l,bool timing):context(c),ledger(l),times(timing?&l.times:nullptr),gate(!timing) {}
  void observe(const helib::Ctxt& c,unsigned parts,unsigned group,const std::string& name,bool inspect=false) {
    Timer timer(times,"validation"); const double capacity=c.bitCapacity(); require(std::isfinite(capacity),"Nonfinite capacity");
    ledger.min_capacity=std::min(ledger.min_capacity,capacity); ledger.all_library_correct&=c.isCorrect();
    if(gate) {
      Json row={{"group",group},{"operation",name},{"expected_parts",parts},{"prime_indices",indices(c.getPrimeSet())},
        {"bit_capacity",capacity},{"library_is_correct",c.isCorrect()}};
      if(inspect) { auto h=handles(c); check_handles(h,parts); row["actual_handles"]=h; ++ledger.handle_checkpoints; }
      ledger.checkpoints.push_back(std::move(row));
    }
  }
  void down(helib::Ctxt& a,const helib::IndexSet& target) {
    require(target.card()>0&&target<=a.getPrimeSet(),"Invalid down-switch target");
    if(a.getPrimeSet()!=target) { Timer t(times,"evaluation_modulus"); a.modDownToSet(target); ++ledger.explicit_mod_changes; }
    require(a.getPrimeSet()==target,"Wrong down-switch result");
  }
  void ordinary(helib::Ctxt& a) { down(a,a.getPrimeSet()&context.getCtxtPrimes()); }
  void add(helib::Ctxt& a,helib::Ctxt b) {
    // Align only when different; do not make special-prime roundtrips for an
    // already compatible group sum. Final output is normalized separately.
    if(a.getPrimeSet()!=b.getPrimeSet()) {
      const auto common=(a.getPrimeSet()&b.getPrimeSet())&context.getCtxtPrimes(); down(a,common); down(b,common);
    }
    Timer t(times,"evaluation_add"); a+=b; ++ledger.adds;
  }
  void mul(helib::Ctxt& a,const helib::Ctxt& b,unsigned pa,unsigned pb) {
    Timer t(times,"evaluation_multiply"); a.multLowLvl(b); ++ledger.products; ledger.component_products+=pa*pb;
  }
  void relin(helib::Ctxt& a,unsigned parts) {
    { Timer t(times,"evaluation_relinearize"); a.reLinearize(); }
    ++ledger.relins; ledger.switched_parts+=parts-2; require(a.inCanonicalForm(),"Relinearization not canonical");
  }
  void rotate(helib::Ctxt& a,const helib::EncryptedArray& ea,unsigned group) {
    require(a.inCanonicalForm(),"Noncanonical rotation input");
    { Timer t(times,"evaluation_rotate"); ea.rotate1D(a,0,-long(group)); }
    ++ledger.rotations; require(a.inCanonicalForm(),"Noncanonical rotation output");
  }
  helib::Ctxt primary(std::vector<helib::Ctxt> in,const core::Cell& c,const Policy& p,unsigned group) {
    require(in.size()==c.input_count(),"Wrong encrypted owner count");
    std::vector<helib::Ctxt> level;
    for(unsigned i=0;i<(c.family==3?4u:1u);++i) {
      const unsigned start=c.family==1?0:3*i;
      helib::Ctxt value=std::move(in[start]); mul(value,in[start+1],2,2);
      observe(value,3,group,"level1_raw",group==0&&i==0);
      if(c.family!=1) { add(value,std::move(in[start+2])); observe(value,3,group,"level1_add"); }
      if(c.family==3&&p.first) { relin(value,3); ordinary(value); observe(value,2,group,"level1_relin",group==0&&i==0); }
      level.push_back(std::move(value));
    }
    unsigned parts= c.family==3&&p.first ? 2 : 3;
    unsigned depth=1;
    while(level.size()>1) {
      ++depth; std::vector<helib::Ctxt> next;
      const unsigned raw_parts=2*parts-1;
      for(unsigned i=0;i<level.size();i+=2) {
        helib::Ctxt value=std::move(level[i]); mul(value,level[i+1],parts,parts);
        observe(value,raw_parts,group,"level"+std::to_string(depth)+"_raw",group==0&&i==0);
        if(depth==2&&p.second) { relin(value,raw_parts); ordinary(value); observe(value,2,group,"level2_relin",group==0&&i==0); }
        next.push_back(std::move(value));
      }
      parts=depth==2&&p.second?2:raw_parts; level=std::move(next);
    }
    require(parts==p.terminal_parts,"Logical terminal arity");
    ordinary(level[0]); observe(level[0],parts,group,"terminal",true); return std::move(level[0]);
  }
};

static Json codec_check() {
  core::Field field; uint64_t seed=0x4144444352545631ULL; Json tests=Json::array(),fixtures=Json::array();
  for(unsigned k:{2u,4u,16u,32u,512u,2048u}) {
    core::AdditiveCRT codec(field,k); Words f(k); for(auto& x:f) x=core::draw(seed);
    const auto v=codec.forward(f); require(codec.inverse(v)==f,"Full-degree CRT inverse");
    for(unsigned x=0;x<k;++x) { require(codec.vanishing(uint16_t(x))==0,"Subspace root"); require(v[x]==core::horner(field,f,uint16_t(x)),"Direct Horner CRT check"); }
    tests.push_back({{"points",k},{"complete_horner_points",k},{"roundtrip_coefficients",k}});
  }
  for(const auto& c:core::cells()) {
    const auto in=core::inputs(c); core::AdditiveCRT codec(field,c.points()); const auto values=core::prepare(c,codec,in);
    Words recovered; std::vector<std::string> forward_fnv; uint64_t input_fnv=14695981039346656037ULL;
    for(const auto& owner:in) input_fnv=core::fnv(owner,input_fnv);
    for(const auto& owner:values) forward_fnv.push_back(std::to_string(core::fnv(owner)));
    for(unsigned job=0;job<c.jobs;++job) {
      Words terminal(codec.size);
      for(unsigned point=0;point<codec.size;++point) {
        const unsigned i=job*codec.size+point;
        if(c.family==1) terminal[point]=field.mul(values[0][i],values[1][i]);
        else {
          std::array<uint16_t,4> terms{};
          for(unsigned j=0;j<(c.family==3?4u:1u);++j) terms[j]=field.mul(values[3*j][i],values[3*j+1][i])^values[3*j+2][i];
          terminal[point]=c.family==2?terms[0]:field.mul(field.mul(terms[0],terms[1]),field.mul(terms[2],terms[3]));
        }
      }
      const auto coefficients=codec.inverse(terminal);
      for(unsigned i=c.degree()+1;i<codec.size;++i) require(!coefficients[i],"Terminal degree bound");
      recovered.insert(recovered.end(),coefficients.begin(),coefficients.begin()+c.length);
    }
    require(recovered==core::oracle(field,c,in),"Terminal compiler versus truncated oracle");
    fixtures.push_back({{"cell",c.name},{"input_fnv64",std::to_string(input_fnv)},
      {"forward_fnv64",forward_fnv},{"recovered_public_fixture_symbols",recovered}});
  }
  return {{"status","CORE_CONVENTIONAL_CODEC_PASS"},{"tests",tests},{"fixtures",fixtures},
    {"encrypted_execution",false},{"benchmark",false},{"security_128_qualified",false}};
}

static helib::Ctxt encrypt_slots(const Words& values,const helib::EncryptedArray& ea,const helib::PubKey& pk,Ledger& l,bool timing) {
  Times* times=timing?&l.times:nullptr; NTL::ZZX plain;
  { Timer t(times,"owner_encoding"); std::vector<NTL::ZZX> slots; slots.reserve(values.size());
    for(auto x:values) slots.push_back(polynomial(x));
    ea.encode(plain,slots); }
  helib::Ctxt out(pk); { Timer t(times,"owner_encryption"); pk.Encrypt(out,plain,2); }
  require(out.inCanonicalForm(),"Nonfresh encrypted input");
  { Timer t(times,"input_serialization"); l.input_bytes+=serialized_size(out); }
  ++l.encryptions; return out;
}
static Words decrypt_slots(const helib::Ctxt& ct,const helib::SecKey& sk,const helib::EncryptedArray& ea,Ledger& l,bool timing) {
  Times* times=timing?&l.times:nullptr;
  { Timer t(times,"output_serialization"); l.output_bytes+=serialized_size(ct); }
  NTL::ZZX plain; { Timer t(times,"recipient_decryption"); sk.Decrypt(plain,ct); }
  Words out;
  { Timer t(times,"recipient_decoding"); std::vector<NTL::ZZX> slots; ea.decode(slots,plain);
    require(slots.size()==size_t(ea.size()),"Decoded slot count"); for(const auto& x:slots) out.push_back(symbol(x)); }
  return out;
}
static Json batch(const core::Cell& c,const std::string& arm,const Policy& p,
  const core::Field& field,const core::AdditiveCRT& codec,const std::vector<Words>& in,const Words& expected,
  const helib::Context& ctx,const helib::EncryptedArray& ea,const helib::PubKey& pk,const helib::SecKey& sk,bool timing) {
  Ledger ledger; Times* times=timing?&ledger.times:nullptr; Evaluator eval(ctx,ledger,timing);
  const auto started=timing?Clock::now():Clock::time_point{};
  Words recovered; Json outputs=Json::array(); bool all_match=true; unsigned slot_checks=0;
  if(arm=="crt") {
    std::vector<Words> prepared; { Timer t(times,"owner_preparation"); prepared=core::prepare(c,codec,in); }
    const unsigned total=c.jobs*codec.size,S=unsigned(ea.size()),groups=(total+S-1)/S;
    Words terminal(total);
    for(unsigned group=0;group<groups;++group) {
      std::vector<helib::Ctxt> encrypted; encrypted.reserve(in.size());
      for(const auto& owner:prepared) {
        Words values(S); const unsigned begin=group*S,count=std::min(S,total-begin);
        { Timer t(times,"owner_packing"); std::copy_n(owner.begin()+begin,count,values.begin()); }
        encrypted.push_back(encrypt_slots(values,ea,pk,ledger,timing));
      }
      helib::Ctxt result=eval.primary(std::move(encrypted),c,p,group);
      const auto values=decrypt_slots(result,sk,ea,ledger,timing);
      { Timer t(times,"validation");
        for(unsigned j=0;j<S;++j) {
          const unsigned i=group*S+j; uint16_t want=0;
          if(i<total) {
            if(c.family==1) want=field.mul(prepared[0][i],prepared[1][i]);
            else { std::array<uint16_t,4> factors{};
              for(unsigned k=0;k<(c.family==3?4u:1u);++k) factors[k]=field.mul(prepared[3*k][i],prepared[3*k+1][i])^prepared[3*k+2][i];
              want=c.family==2?factors[0]:field.mul(field.mul(factors[0],factors[1]),field.mul(factors[2],factors[3])); }
            terminal[i]=values[j];
          }
          all_match&=values[j]==want; ++slot_checks;
        }
      }
      outputs.push_back({{"group",group},{"parts",p.terminal_parts},{"prime_indices",indices(result.getPrimeSet())},
        {"bit_capacity",result.bitCapacity()},{"library_is_correct",result.isCorrect()}});
    }
    for(unsigned job=0;job<c.jobs;++job) {
      Words coeff;
      { Timer t(times,"recipient_interpolation"); coeff=codec.inverse(Words(terminal.begin()+job*codec.size,terminal.begin()+(job+1)*codec.size)); }
      { Timer t(times,"validation"); for(unsigned j=c.degree()+1;j<codec.size;++j) all_match&=coeff[j]==0; }
      recovered.insert(recovered.end(),coeff.begin(),coeff.begin()+c.length);
    }
    require(ledger.encryptions==c.input_count()*groups&&ledger.products==(c.family==3?7u:1u)*groups,"Primary input/product inventory");
    require(ledger.adds==(c.family==1?0u:c.family==2?1u:4u)*groups,"Primary addition inventory");
    require(ledger.relins==(c.family==3?4*p.first+2*p.second:0u)*groups&&ledger.rotations==0,"Primary switching inventory");
    require(ledger.component_products==p.products_per_group*groups,"Primary component products");
  } else {
    require(ea.size()==512&&c.length==256&&c.jobs==16,"BSGS profile mismatch");
    for(unsigned block=0;block<8;++block) {
      std::vector<helib::Ctxt> babies; babies.reserve(16);
      for(unsigned r=0;r<16;++r) {
        Words values(512); { Timer t(times,"owner_preparation");
          for(unsigned q=0;q<2;++q) for(unsigned j=0;j<256;++j) values[slot(q,j)]=in[0][256*(2*block+q)+(j+r)%256]; }
        babies.push_back(encrypt_slots(values,ea,pk,ledger,timing));
      }
      std::unique_ptr<helib::Ctxt> raw,canonical;
      for(unsigned v=0;v<16;++v) {
        std::unique_ptr<helib::Ctxt> sum;
        for(unsigned r=0;r<16;++r) {
          Words values(512); { Timer t(times,"owner_preparation");
            for(unsigned q=0;q<2;++q) for(unsigned j=0;j<256;++j) {
              const unsigned y=(j+256-16*v)%256,i=(j+r)%256;
              values[slot(q,j)]=i<=y?in[1][256*(2*block+q)+y-i]:0;
            } }
          auto diagonal=encrypt_slots(values,ea,pk,ledger,timing); helib::Ctxt value=babies[r];
          eval.mul(value,diagonal,2,2);
          if(sum) eval.add(*sum,std::move(value)); else sum=std::make_unique<helib::Ctxt>(std::move(value));
        }
        eval.observe(*sum,3,block,"bsgs_group_raw",block==0&&v==0);
        if(v==0) raw=std::move(sum);
        else {
          eval.relin(*sum,3); eval.rotate(*sum,ea,v); eval.observe(*sum,2,block,"bsgs_group_rotated",block==0&&v==1);
          if(canonical) eval.add(*canonical,std::move(*sum)); else canonical=std::move(sum);
        }
      }
      require(raw&&canonical,"Incomplete BSGS groups"); eval.ordinary(*raw); eval.ordinary(*canonical); eval.add(*raw,std::move(*canonical));
      eval.observe(*raw,3,block,"terminal",true);
      const auto values=decrypt_slots(*raw,sk,ea,ledger,timing);
      for(unsigned q=0;q<2;++q) for(unsigned j=0;j<256;++j) { recovered.push_back(values[slot(q,j)]); ++slot_checks; }
      outputs.push_back({{"group",block},{"parts",3},{"prime_indices",indices(raw->getPrimeSet())},
        {"bit_capacity",raw->bitCapacity()},{"library_is_correct",raw->isCorrect()}});
    }
    require(ledger.encryptions==2176&&ledger.products==2048&&ledger.component_products==8192&&ledger.adds==2040,
      "BSGS arithmetic inventory");
    require(ledger.relins==120&&ledger.rotations==120&&ledger.switched_parts==120,"BSGS switching inventory");
  }
  { Timer t(times,"validation"); all_match&=recovered==expected; }
  bool margin=true;
  for(const auto& row:outputs) margin&=row.at("bit_capacity").get<double>()>=10&&row.at("library_is_correct").get<bool>();
  Json result=ledger.json(); result["output_profiles"]=outputs; result["recovered_public_fixture_symbols"]=recovered;
  result["all_outputs_match"]=all_match; result["terminal_slots_checked"]=slot_checks; result["terminal_capacity_gate"]=margin;
  result["functional_admitted"]=all_match&&margin&&ledger.all_library_correct;
  if(timing) { result["seconds"]=ledger.times; result["batch_wall_seconds"]=std::chrono::duration<double>(Clock::now()-started).count(); }
  return result;
}

int main(int argc,char** argv) {
  try {
    helib::helog.setLogToStderr(); NTL::SetNumThreads(1);
    if(argc==2&&std::string(argv[1])=="public-codec") { std::cout<<codec_check().dump()<<'\n'; return 0; }
    require(argc==7,"Use supervisor: MODE ARM CELL M BITS POLICY");
    const std::string mode=argv[1],arm=argv[2]; const auto c=core::cell(argv[3]);
    const long m=std::stol(argv[4]),bits=std::stol(argv[5]); const auto p=policy(c,arm,argv[6]);
    require(mode=="profile"||mode=="gate"||mode=="sample","Unknown execution mode");
    require(m==4369||m==13107||m==21845||m==65535,"Unlisted conductor");
    require(bits==20||bits==60||bits==120||bits==180||bits==240,"Unlisted modulus request");
    require(arm!="b16"||m==13107,"Unproved BSGS layout");
    const bool timing=mode=="sample"; Times setup; Times* times=timing?&setup:nullptr;
    std::unique_ptr<helib::Context> ctx; std::unique_ptr<helib::EncryptedArray> ea;
    NTL::SetSeed(NTL::ZZ(20260908)); // Public context construction only; reseed before keygen.
    { Timer t(times,"public_context_codec");
      auto builder=helib::ContextBuilder<helib::BGV>().m(m).p(2).r(1).bits(bits).c(2).skHwt(0).bootstrappable(false);
      if(arm=="b16") builder.gens({4627,12853}).ords({16,32});
      ctx.reset(new helib::Context(builder.build())); NTL::ZZX G;
      for(long j:{0L,1L,3L,12L,16L}) NTL::SetCoeff(G,j,1);
      ea=std::make_unique<helib::EncryptedArray>(*ctx,G);
    }
    auto desc=profile(*ctx,*ea,bits,arm);
    double adjusted_stdev=NTL::to_double(ctx->getStdev());
    if(ctx->getZMStar().getPow2()==0) adjusted_stdev*=std::sqrt(double(ctx->getM()));
    const double q_log_alpha=(ctx->logOfProduct(ctx->getCtxtPrimes())-std::log(adjusted_stdev))/std::log(2.0);
    const double q_only=helib::lweEstimateSecurity(int(ctx->getPhiM()),q_log_alpha,int(ctx->getHwt()));
    const double effective=p.matrices==0?q_only:ctx->securityLevel();
    desc["published_q_library_heuristic_NOT_CERTIFICATION"]=q_only;
    desc["effective_library_heuristic_NOT_CERTIFICATION"]=effective;
    desc["effective_library_128_screen"]=effective>=128;
    desc["screen_modulus"]=p.matrices==0?"Q":"QP";
    desc["assumed_switching_matrices"]=p.matrices;
    desc["adjusted_library_stdev"]=adjusted_stdev;
    if(mode=="profile") {
      auto check=public_carrier(*ctx,*ea,arm);
      std::cout<<Json({{"status","CORE_CONVENTIONAL_PROFILE_PASS"},{"profile",desc},{"checks",check},
        {"encrypted_execution",false},{"keys_generated",0},{"benchmark",false},{"security_128_qualified",false}}).dump()<<'\n'; return 0;
    }
    require(effective>=128,"Fails actual-public-modulus library security screen");
    require(!helib::isSetAutomorphVals()&&!helib::isSetAutomorphVals2(),"Automorphism recording disables real execution");
    std::unique_ptr<core::Field> field; std::unique_ptr<core::AdditiveCRT> codec;
    { Timer t(times,"public_field_crt_tables"); field=std::make_unique<core::Field>(); codec=std::make_unique<core::AdditiveCRT>(*field,c.points()); }
    std::unique_ptr<helib::SecKey> sk; std::unique_ptr<helib::PubKey> pk;
    { Timer t(times,"keys_and_hints"); entropy_seed(); sk=std::make_unique<helib::SecKey>(*ctx);
      require(sk->GenSecKey(2,1)==0,"Unexpected key id");
      if(p.matrices) sk->GenKeySWmatrix(2,1,0,0,2);
      if(arm=="crt"&&p.matrices==3) for(long s:{3L,4L}) sk->GenKeySWmatrix(s,1,0,0,2);
      if(arm=="b16") { std::set<long> autos;
        for(unsigned v=1;v<16;++v) autos.insert(ctx->getZMStar().genToPow(0,-long(v)));
        helib::addTheseMatrices(*sk,autos);
      }
      pk=std::make_unique<helib::PubKey>(*sk);
    }
    require(typeid(*pk)==typeid(helib::PubKey)&&pk->keySWlist().size()==p.matrices,"Wrong public key/matrix count");
    require(!pk->isBootstrappable(),"Unexpected bootstrapping publication");
    Json matrix_inventory=Json::array(); std::set<std::pair<long,long>> expected_matrices,actual_matrices;
    if(p.matrices) expected_matrices.insert({2,1});
    if(arm=="crt"&&p.matrices==3) { expected_matrices.insert({3,1}); expected_matrices.insert({4,1}); }
    if(arm=="b16") for(unsigned v=1;v<16;++v) {
      const long k=ctx->getZMStar().genToPow(0,-long(v)); expected_matrices.insert({1,k});
      require(pk->getNextKSWmatrix(k,0).fromKey.getPowerOfX()==k,"Unexpected multi-hop rotation");
    }
    for(const auto& matrix:pk->keySWlist()) {
      require(matrix.fromKey.getSecretKeyID()==0&&matrix.toKeyID==0&&matrix.ptxtSpace==2,"Wrong switching key graph");
      actual_matrices.insert({matrix.fromKey.getPowerOfS(),matrix.fromKey.getPowerOfX()});
      matrix_inventory.push_back({{"power_of_s",matrix.fromKey.getPowerOfS()},
        {"power_of_x",matrix.fromKey.getPowerOfX()},{"columns",matrix.NumCols()}});
    }
    require(actual_matrices==expected_matrices,"Wrong actual switching powers");
    uint64_t key_bytes=0; { Timer t(times,"public_key_serialization"); key_bytes=serialized_size(*pk); }
    const auto in=core::inputs(c); const auto expected=core::oracle(*field,c,in);
    uint64_t input_fnv=14695981039346656037ULL; for(const auto& owner:in) input_fnv=core::fnv(owner,input_fnv);
    std::cout<<Json({{"event","core_setup_complete"},{"profile",desc},{"switching_matrices",matrix_inventory}}).dump()<<'\n'<<std::flush;
    Json batches=Json::array(); bool admitted=true;
    for(unsigned index=0;index<2;++index) {
      auto result=batch(c,arm,p,*field,*codec,in,expected,*ctx,*ea,*pk,*sk,timing);
      result["index"]=index; admitted&=result.at("functional_admitted").get<bool>(); batches.push_back(std::move(result));
      std::cout<<Json({{"event","core_batch_complete"},{"index",index},{"functional_admitted",batches.back().at("functional_admitted")}}).dump()<<'\n'<<std::flush;
    }
    struct rusage usage{}; getrusage(RUSAGE_SELF,&usage);
    Json result={{"status",admitted?"CORE_CONVENTIONAL_GATE_PASS":"CORE_CONVENTIONAL_GATE_REJECT"},
      {"cell",c.name},{"compiler",arm},{"policy",p.name},{"profile",desc},{"batches",batches},
      {"fixture_fnv64",std::to_string(input_fnv)},{"switching_matrices",matrix_inventory},
      {"public_key_including_hints_bytes_serialized",key_bytes},{"peak_rss_kib",usage.ru_maxrss},
      {"encrypted_execution",true},{"benchmark",timing},{"bootstrapping",false},{"process_isolation",false},
      {"security_128_qualified",false},{"secret_keys_exported",false},{"phase_diagnostics_exported",false}};
    if(timing) result["setup_seconds"]=setup;
    std::cout<<result.dump()<<'\n'; return admitted?0:2;
  } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
