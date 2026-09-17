// Untimed stock-BGV depth-one prepared composition, four full-field jobs.
// Actual PubKey copy prevents virtual dispatch into secret-key encryption.
#include <helib/helib.h>
#include <NTL/BasicThreadPool.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <vector>
#include "composition_fixture.h"

static void require(bool x,const char* why){if(!x)throw std::runtime_error(why);}
static NTL::ZZX polynomial(uint16_t x){
    NTL::ZZX p;for(unsigned j=0;j<16;++j)if((x>>j)&1)NTL::SetCoeff(p,j,1);return p;
}
static uint16_t symbol(const NTL::ZZX& p){
    require(NTL::deg(p)<16,"Non-field output");unsigned out=0;
    for(long j=0;j<=NTL::deg(p);++j){require(NTL::coeff(p,j)==0||NTL::coeff(p,j)==1,"Nonbinary output");if(NTL::IsOne(NTL::coeff(p,j)))out|=1u<<j;}
    return uint16_t(out);
}

// No private key, owner series, plaintext, RNG or diagnostic callback enters
// this evaluator. This same-process API check is not process isolation.
class PublicContraction {
    helib::Ctxt sum;
    unsigned products=0;
public:
    explicit PublicContraction(const helib::Ctxt& constant):sum(constant){}
    void consume(helib::Ctxt f,const helib::Ctxt& a){
        require(f.inCanonicalForm()&&a.inCanonicalForm(),"Nonfresh product input");
        f.multLowLvl(a);require(!f.inCanonicalForm(),"Product unexpectedly relinearized");
        sum+=f;++products;
    }
    helib::Ctxt finish(){
        require(products==255,"Wrong contraction length");
        sum.reLinearize();require(sum.inCanonicalForm(),"Final relinearization failed");
        return sum;
    }
};

int main(int argc,char** argv){
    try{
        require(argc==2,"Use the bounded supervisor");
        const std::string mode=argv[1];
        require(mode=="--public-fixture"||mode=="--encrypted-k8","Unknown mode");
        const auto in=fixture::inputs();
        if(mode=="--public-fixture"){
            std::cout<<"{\"status\":\"PUBLIC_FIXTURE_PASS\",\"fixture_fnv64\":\""<<fixture::checksum(in)<<"\",\"inputs\":[";
            bool first=true;for(unsigned j=0;j<16;++j)for(const auto* v:{&in.f[j],&in.g[j]})for(auto x:*v){if(!first)std::cout<<',';first=false;std::cout<<x;}
            std::cout<<"],\"keys_generated\":0,\"encrypted_execution\":false}\n";return 0;
        }
        NTL::SetNumThreads(1);
        std::array<unsigned char,32> entropy{};
        {std::ifstream os_random("/dev/urandom",std::ios::binary);require(bool(os_random.read(reinterpret_cast<char*>(entropy.data()),entropy.size())),"OS entropy unavailable");}
        NTL::SetSeed(NTL::ZZFromBytes(entropy.data(),entropy.size()));entropy.fill(0);
        auto context=helib::ContextBuilder<helib::BGV>().m(21845).p(2).r(1)
            .bits(120).c(2).skHwt(0).bootstrappable(false).build();
        require(context.securityLevel()>=128,"Fails preliminary library filter");
        NTL::ZZX G;for(long j:{0L,1L,3L,12L,16L})NTL::SetCoeff(G,j,1);
        helib::EncryptedArray ea(context,G);
        require(ea.size()==1024&&ea.getDegree()==16,"Wrong full-field interface");
        helib::SecKey private_key(context);private_key.GenSecKey(2,2);
        const helib::PubKey public_key(private_key);
        require(typeid(public_key)==typeid(helib::PubKey),"Not a public-key-only object");
        require(public_key.keySWlist().size()==1,"Unexpected evaluation keys");
        std::cout<<"{\"event\":\"setup_complete\",\"jobs\":4,\"key_switch_matrices\":1}\n"<<std::flush;

        unsigned encryptions=0,roundtrips=0;
        auto encrypt=[&](const std::vector<NTL::ZZX>& slots){
            NTL::ZZX p;ea.encode(p,slots);std::vector<NTL::ZZX> decoded;
            ea.decode(decoded,p);require(decoded==slots,"Owner full-field codec mismatch");++roundtrips;
            helib::Ctxt c(public_key);public_key.Encrypt(c,p,2);++encryptions;return c;
        };
        std::vector<NTL::ZZX> constant(1024);
        // [z^j]g^0=delta_{j,0}; broadcasting f0 would be an incorrect circuit.
        for(unsigned job=0;job<4;++job)constant[job*256]=polynomial(in.f[job][0]);
        PublicContraction evaluator(encrypt(constant));
        std::array<fixture::Jet,4> powers{};
        for(auto& p:powers)p[0]=1;
        for(unsigned i=1;i<256;++i){
            std::vector<NTL::ZZX> f(1024),a(1024);
            for(unsigned job=0;job<4;++job){
                powers[job]=fixture::series_product(powers[job],in.g[job]);
                for(unsigned j=0;j<256;++j){f[job*256+j]=polynomial(in.f[job][i]);a[job*256+j]=polynomial(powers[job][j]);}
            }
            auto cf=encrypt(f),ca=encrypt(a);evaluator.consume(std::move(cf),ca);
            if(i%64==0)std::cout<<"{\"event\":\"contraction_progress\",\"products\":"<<i<<"}\n"<<std::flush;
        }
        auto result=evaluator.finish();require(encryptions==511&&roundtrips==511,"Wrong preparation inventory");
        require(result.bitCapacity()>0,"No estimated decryption capacity remains");
        NTL::ZZX plaintext;private_key.Decrypt(plaintext,result);
        std::vector<NTL::ZZX> decoded;ea.decode(decoded,plaintext);
        std::vector<uint16_t> recovered;recovered.reserve(1024);
        for(unsigned job=0;job<4;++job){
            auto expected=fixture::horner(in.f[job],in.g[job]);
            for(unsigned j=0;j<256;++j){auto x=symbol(decoded[job*256+j]);require(x==expected[j],"Encrypted composition differs from Horner");recovered.push_back(x);}
        }
        std::cout<<std::setprecision(17)<<"{\"status\":\"HELIB_K8_ENCRYPTED_CORRESPONDENCE_PASS\",\"m\":21845,\"dimension\":16384,\"slots\":1024,\"jobs\":4,\"length\":256"
          <<",\"fixture_id\":\"composition-l256-v1\",\"fixture_jobs\":[0,1,2,3],\"fixture_fnv64\":\""<<fixture::checksum(in)<<'"'
          <<",\"requested_bits\":120,\"digits\":2,\"sk_hwt\":0,\"field_polynomial\":\"0x1100b\""
          <<",\"library_security_estimate_NOT_CERTIFICATION\":"<<context.securityLevel()
          <<",\"public_key_copy\":true,\"secret_keys\":1,\"key_switch_matrices\":1,\"fresh_encryptions\":"<<encryptions
          <<",\"owner_codec_roundtrips\":"<<roundtrips<<",\"private_products\":255,\"relinearizations\":1,\"rotations\":0,\"multiplicative_depth\":1"
          <<",\"public_output_bit_capacity\":"<<result.bitCapacity()<<",\"ciphertext_primes\":[";
        bool first=true;for(long i:context.getCtxtPrimes()){if(!first)std::cout<<',';first=false;std::cout<<'"'<<context.ithPrime(i)<<'"';}
        std::cout<<"],\"special_primes\":[";first=true;
        for(long i:context.getSpecialPrimes()){if(!first)std::cout<<',';first=false;std::cout<<'"'<<context.ithPrime(i)<<'"';}
        std::cout<<"],\"output_primes\":[";first=true;
        for(long i:result.getPrimeSet()){if(!first)std::cout<<',';first=false;std::cout<<'"'<<context.ithPrime(i)<<'"';}
        std::cout<<"],\"recovered_public_fixture_symbols\":[";first=true;
        for(auto x:recovered){if(!first)std::cout<<',';first=false;std::cout<<x;}
        std::cout<<"],\"symbols_checked\":1024,\"worker_threads\":1,\"encrypted_execution\":true,\"benchmark\":false,\"bootstrapping\":false,\"process_isolation\":false}\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
