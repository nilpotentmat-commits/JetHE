// Pinned HElib's actual full-extension-field codec, not the custom tensor codec.
// No secret key, ciphertext, bootstrapping material, or timing is generated.
#include <helib/helib.h>
#include <NTL/GF2X.h>
#include <NTL/BasicThreadPool.h>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

static void require(bool x,const char* why){if(!x)throw std::runtime_error(why);}
static NTL::ZZX polynomial(uint16_t x){
    NTL::ZZX p;for(unsigned j=0;j<16;++j)if((x>>j)&1)NTL::SetCoeff(p,j,1);return p;
}
static NTL::GF2X binary(const NTL::ZZX& x){
    NTL::GF2X out;for(long j=0;j<=NTL::deg(x);++j)if(NTL::IsOdd(NTL::coeff(x,j)))NTL::SetCoeff(out,j);return out;
}
static NTL::ZZX integer(const NTL::GF2X& x){
    NTL::ZZX out;for(long j=0;j<=NTL::deg(x);++j)if(NTL::IsOne(NTL::coeff(x,j)))NTL::SetCoeff(out,j,1);return out;
}
static uint16_t field_product(unsigned a,unsigned b){
    unsigned out=0;while(b){if(b&1)out^=a;b>>=1;a<<=1;if(a&65536)a^=0x1100b;}return uint16_t(out);
}
int main(int argc,char** argv){
    try{
        require(argc==2&&std::string(argv[1])=="--public-codec","Use the bounded public preflight supervisor");
        NTL::SetNumThreads(1);
        constexpr long requested_bits=120;
        auto context=helib::ContextBuilder<helib::BGV>().m(4369).p(2).r(1)
            .bits(requested_bits).c(2).skHwt(0).bootstrappable(false).build();
        NTL::ZZX G;for(long j:{0L,1L,3L,12L,16L})NTL::SetCoeff(G,j,1);
        helib::EncryptedArray ea(context,G); // Default G=X would restrict to F2.
        require(context.getPhiM()==4096&&context.getOrdP()==16&&ea.size()==256&&ea.getDegree()==16,"Wrong field capacity");
        NTL::GF2XModulus quotient(binary(context.getZMStar().getPhimX()));
        std::mt19937 public_fixture(2026090833u); // Public algebra only, NOT crypto coins.
        unsigned roundtrips=0,products=0;
        for(unsigned trial=0;trial<8;++trial){
            std::vector<NTL::ZZX> a(256),b(256),expected(256),decoded;
            for(unsigned i=0;i<256;++i){
                uint16_t x=uint16_t(public_fixture()),y=uint16_t(public_fixture());
                a[i]=polynomial(x);b[i]=polynomial(y);expected[i]=polynomial(field_product(x,y));
            }
            NTL::ZZX pa,pb;ea.encode(pa,a);ea.encode(pb,b);
            ea.decode(decoded,pa);require(decoded==a,"First HElib field roundtrip");
            ea.decode(decoded,pb);require(decoded==b,"Second HElib field roundtrip");roundtrips+=2;
            NTL::GF2X product;NTL::MulMod(product,binary(pa),binary(pb),quotient);
            ea.decode(decoded,integer(product));require(decoded==expected,"HElib field multiplication mapping");++products;
        }
        std::cout<<std::setprecision(17)
            <<"{\"status\":\"HELIB_PUBLIC_FIELD_PREFLIGHT_ONLY\",\"pin\":\"3e337a66a91a92d49de6a9505340826b0eb71081\","
            <<"\"m\":4369,\"dimension\":4096,\"slots\":256,\"field_polynomial\":\"0x1100b\","
            <<"\"explicit_field_constructor\":true,\"requested_bits\":"<<requested_bits
            <<",\"library_security_estimate_NOT_CERTIFICATION\":"<<context.securityLevel()
            <<",\"ciphertext_primes\":[";
        bool first=true;for(long i:context.getCtxtPrimes()){if(!first)std::cout<<',';first=false;std::cout<<context.ithPrime(i);}
        std::cout<<"],\"special_primes\":[";
        first=true;for(long i:context.getSpecialPrimes()){if(!first)std::cout<<',';first=false;std::cout<<context.ithPrime(i);}
        std::cout<<"],\"roundtrips\":"<<roundtrips<<",\"full_slot_product_checks\":"<<products
            <<",\"worker_threads\":1,\"keys_generated\":0,\"encrypted_execution\":false,\"benchmark\":false,\"bootstrapping\":false}\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
