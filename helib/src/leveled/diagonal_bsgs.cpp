// Untimed prepared-baby encrypted-diagonal BSGS composition correspondence.
// Preserve matrix_k8.cpp as the independently executed zero-rotation control.
#include <helib/helib.h>
#include <NTL/BasicThreadPool.h>
#include <NTL/GF2X.h>
#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <vector>
#include "composition_fixture.h"

static void require(bool x,const char* why){if(!x)throw std::runtime_error(why);}
static constexpr long M=21845,ETA=8996,GAMMA=21591;
static unsigned slot(unsigned job,unsigned j){return 64*(j/16)+16*job+j%16;}
static NTL::ZZX polynomial(uint16_t x){
    NTL::ZZX p;for(unsigned j=0;j<16;++j)if((x>>j)&1)NTL::SetCoeff(p,j,1);return p;
}
static uint16_t symbol(const NTL::ZZX& p){
    require(NTL::deg(p)<16,"Non-field output");unsigned out=0;
    for(long j=0;j<=NTL::deg(p);++j){require(NTL::coeff(p,j)==0||NTL::coeff(p,j)==1,"Nonbinary output");if(NTL::IsOne(NTL::coeff(p,j)))out|=1u<<j;}
    return uint16_t(out);
}
static void profile(const helib::Context& c){
    std::cout<<std::setprecision(17)<<"\"m\":21845,\"dimension\":16384,\"slots\":1024,\"jobs\":4,\"length\":256"
      <<",\"generators\":[8996,21591],\"orders\":[16,64],\"native_giant_axis\":0"
      <<",\"slot_layout\":\"64*floor(j/16)+16*job+(j mod 16)\",\"field_polynomial\":\"0x1100b\""
      <<",\"requested_bits\":120,\"digits\":2,\"sk_hwt\":0"
      <<",\"library_security_estimate_NOT_CERTIFICATION\":"<<c.securityLevel()<<",\"ciphertext_primes\":[";
    bool first=true;for(long i:c.getCtxtPrimes()){if(!first)std::cout<<',';first=false;std::cout<<'"'<<c.ithPrime(i)<<'"';}
    std::cout<<"],\"special_primes\":[";first=true;
    for(long i:c.getSpecialPrimes()){if(!first)std::cout<<',';first=false;std::cout<<'"'<<c.ithPrime(i)<<'"';}
    std::cout<<']';
}
static void layout_check(const helib::Context& c,const helib::EncryptedArray& ea){
    const auto& z=c.getZMStar();
    require(c.getPhiM()==16384&&ea.size()==1024&&ea.getDegree()==16,"Wrong full-field interface");
    require(z.numOfGens()==2&&z.OrderOf(0)==16&&z.OrderOf(1)==64&&z.SameOrd(0),"Wrong native axis");
    require(z.ZmStarGen(0)==ETA&&z.ZmStarGen(1)==GAMMA,"Wrong generators");
    std::set<long> units;
    for(unsigned q=0;q<4;++q)for(unsigned j=0;j<256;++j){
        long i=slot(q,j),h=j/16,a=16*q+j%16;
        require(z.coordinate(0,i)==h&&z.coordinate(1,i)==a,"Wrong cube coordinates");
        long rep=NTL::MulMod(NTL::PowerMod(ETA,h,M),NTL::PowerMod(GAMMA,a,M),M);
        require(z.ith_rep(i)==rep,"Wrong full-field representative");
        for(unsigned k=0;k<16;++k){require(units.insert(rep).second,"Repeated Frobenius coset");rep=NTL::MulMod(rep,2,M);}
    }
    require(units.size()==16384,"Incomplete unit transversal");
}

// Public-only same-process evaluator. Owners and recipient remain in harness.
// Each raw degree-two group is explicitly relinearized BEFORE rotate1D.
class PublicBSGS {
    const std::vector<helib::Ctxt>& babies;
    const helib::EncryptedArray& ea;
    std::unique_ptr<helib::Ctxt> group,sum;
    unsigned groups=0,products=0,adds=0,relins=0,rotations=0,in_group=0;
public:
    PublicBSGS(const std::vector<helib::Ctxt>& b,const helib::EncryptedArray& e):babies(b),ea(e){require(b.size()==16,"Wrong baby count");}
    void consume(unsigned r,const helib::Ctxt& diagonal){
        require(r<16&&!(groups==0&&r==1),"Wrong diagonal index");
        helib::Ctxt p(babies[r]);
        require(p.inCanonicalForm()&&diagonal.inCanonicalForm(),"Nonfresh product input");
        p.multLowLvl(diagonal);require(!p.inCanonicalForm(),"Implicit product relinearization");
        if(group){*group+=p;++adds;}else group=std::make_unique<helib::Ctxt>(p);
        ++products;++in_group;
    }
    void finish_group(){
        require(group&&groups<16&&in_group==(groups?16u:15u),"Wrong group length");
        group->reLinearize();++relins;require(group->inCanonicalForm(),"Group not canonical");
        if(groups){ea.rotate1D(*group,0,-long(groups));++rotations;}
        require(group->inCanonicalForm(),"Rotation not canonical");
        if(sum){*sum+=*group;++adds;}else sum=std::make_unique<helib::Ctxt>(*group);
        group.reset();in_group=0;++groups;
    }
    helib::Ctxt finish(){
        require(sum&&!group&&groups==16&&products==255&&adds==254&&relins==16&&rotations==15,"Wrong executed inventory");
        return *sum;
    }
};

int main(int argc,char** argv){
    try{
        require(argc==2,"Use the bounded supervisor");const std::string mode=argv[1];
        require(mode=="--public-layout"||mode=="--encrypted-b16","Unknown mode");
        NTL::SetNumThreads(1);const auto in=fixture::inputs();
        auto context=helib::ContextBuilder<helib::BGV>().m(M).p(2).r(1)
          .gens({ETA,GAMMA}).ords({16,64}).bits(120).c(2).skHwt(0).bootstrappable(false).build();
        require(context.securityLevel()>=128,"Fails preliminary library filter");
        NTL::ZZX G;for(long j:{0L,1L,3L,12L,16L})NTL::SetCoeff(G,j,1);
        helib::EncryptedArray ea(context,G);layout_check(context,ea);
        if(mode=="--public-layout"){
            // Independent ring substitution, not the ciphertext rotation API.
            std::vector<NTL::ZZX> slots(1024),decoded;
            for(unsigned q=0;q<4;++q)for(unsigned j=0;j<256;++j)slots[slot(q,j)]=polynomial(in.f[q][j]);
            NTL::ZZX encoded;ea.encode(encoded,slots);ea.decode(decoded,encoded);require(decoded==slots,"Full-field codec mismatch");
            NTL::GF2X phi,a;NTL::conv(phi,context.getZMStar().getPhimX());NTL::conv(a,encoded);
            NTL::GF2XModulus modulus(phi);
            for(unsigned v=1;v<16;++v){
                const long k=context.getZMStar().genToPow(0,-long(v));
                NTL::GF2X xk,mapped;NTL::PowerXMod(xk,k,modulus);NTL::CompMod(mapped,a,xk,modulus);
                NTL::ZZX transformed;NTL::conv(transformed,mapped);ea.decode(decoded,transformed);
                for(unsigned q=0;q<4;++q)for(unsigned j=0;j<256;++j)
                    require(decoded[slot(q,j)]==slots[slot(q,(j+16*v)%256)],"Native full-field rotation mismatch");
            }
            std::cout<<"{\"status\":\"HELIB_DIAGONAL_LAYOUT_PASS\",";profile(context);
            std::cout<<",\"fixture_fnv64\":\""<<fixture::checksum(in)<<"\",\"representatives_checked\":1024,\"units_checked\":16384"
              <<",\"polynomial_automorphisms_checked\":15,\"rotated_field_symbols_checked\":15360,\"keys_generated\":0,\"encrypted_execution\":false,\"benchmark\":false}\n";
            return 0;
        }
        std::array<unsigned char,32> entropy{};
        {std::ifstream os_random("/dev/urandom",std::ios::binary);require(bool(os_random.read(reinterpret_cast<char*>(entropy.data()),entropy.size())),"OS entropy unavailable");}
        NTL::SetSeed(NTL::ZZFromBytes(entropy.data(),entropy.size()));entropy.fill(0);
        require(!helib::isSetAutomorphVals()&&!helib::isSetAutomorphVals2(),"Automorphism recording would skip execution");
        helib::SecKey private_key(context);private_key.GenSecKey(2,2);
        std::set<long> autos;
        for(unsigned v=1;v<16;++v)autos.insert(context.getZMStar().genToPow(0,-long(v)));
        helib::addTheseMatrices(private_key,autos);
        const helib::PubKey public_key(private_key);
        require(typeid(public_key)==typeid(helib::PubKey)&&public_key.keySWlist().size()==16,"Wrong public-key/matrix interface");
        for(long k:autos)require(public_key.getNextKSWmatrix(k,0).fromKey.getPowerOfX()==k,"Rotation uses multiple hops");
        std::cout<<"{\"event\":\"setup_complete\",\"jobs\":4,\"key_switch_matrices\":16}\n"<<std::flush;

        unsigned encryptions=0,roundtrips=0;
        auto encrypt=[&](const std::vector<NTL::ZZX>& slots){
            NTL::ZZX p;ea.encode(p,slots);std::vector<NTL::ZZX> decoded;ea.decode(decoded,p);
            require(decoded==slots,"Owner codec mismatch");++roundtrips;
            helib::Ctxt c(public_key);public_key.Encrypt(c,p,2);++encryptions;return c;
        };
        std::vector<helib::Ctxt> babies;babies.reserve(16);
        for(unsigned r=0;r<16;++r){
            std::vector<NTL::ZZX> f(1024);
            for(unsigned q=0;q<4;++q)for(unsigned j=0;j<256;++j)f[slot(q,j)]=polynomial(in.f[q][(j+r)%256]);
            babies.push_back(encrypt(f));
        }
        // Owner g prepares only its own powers; col0=e0, retaining A00=1.
        std::array<std::array<fixture::Jet,256>,4> columns{};
        for(unsigned q=0;q<4;++q){
            require(in.g[q][0]==0,"Unsupported constant term");columns[q][0][0]=1;
            for(unsigned i=1;i<256;++i)columns[q][i]=fixture::series_product(columns[q][i-1],in.g[q]);
        }
        PublicBSGS evaluator(babies,ea);
        for(unsigned h=0;h<256;h+=16){
            for(unsigned r=0;r<16;++r){
                if(h+r==1)continue;
                std::vector<NTL::ZZX> diagonal(1024);
                for(unsigned q=0;q<4;++q)for(unsigned j=0;j<256;++j){
                    unsigned y=(j+256-h)%256,i=(j+r)%256;
                    diagonal[slot(q,j)]=polynomial(columns[q][i][y]);
                }
                auto d=encrypt(diagonal);evaluator.consume(r,d);
            }
            evaluator.finish_group();
            if(h%64==48)std::cout<<"{\"event\":\"bsgs_progress\",\"groups\":"<<h/16+1<<"}\n"<<std::flush;
        }
        auto result=evaluator.finish();require(encryptions==271&&roundtrips==271,"Wrong owner inventory");
        require(result.bitCapacity()>0,"No estimated decryption capacity remains");
        NTL::ZZX plaintext;private_key.Decrypt(plaintext,result);std::vector<NTL::ZZX> decoded;ea.decode(decoded,plaintext);
        std::vector<uint16_t> recovered;recovered.reserve(1024);
        for(unsigned q=0;q<4;++q){
            const auto expected=fixture::horner(in.f[q],in.g[q]);
            for(unsigned j=0;j<256;++j){const auto x=symbol(decoded[slot(q,j)]);require(x==expected[j],"Encrypted BSGS differs from Horner");recovered.push_back(x);}
        }
        std::cout<<"{\"status\":\"HELIB_DIAGONAL_B16_ENCRYPTED_PASS\",";profile(context);
        std::cout<<",\"fixture_id\":\"composition-l256-v1\",\"fixture_jobs\":[0,1,2,3],\"fixture_fnv64\":\""<<fixture::checksum(in)<<'"'
          <<",\"baby_width\":16,\"prepared_babies\":true,\"public_key_copy\":true,\"secret_keys\":1,\"key_switch_matrices\":16"
          <<",\"fresh_encryptions\":"<<encryptions<<",\"owner_codec_roundtrips\":"<<roundtrips
          <<",\"private_products\":255,\"group_relinearizations\":16,\"physical_automorphisms\":15,\"rotation_key_switches\":15"
          <<",\"raw_group_additions\":239,\"canonical_output_additions\":15,\"public_mask_multiplications\":0,\"multiplicative_depth\":1"
          <<",\"direct_rotation_matrices_checked\":15,\"automorphism_recording_disabled\":true"
          <<",\"public_output_bit_capacity\":"<<result.bitCapacity()<<",\"output_primes\":[";
        bool first=true;for(long i:result.getPrimeSet()){if(!first)std::cout<<',';first=false;std::cout<<'"'<<context.ithPrime(i)<<'"';}
        std::cout<<"],\"recovered_public_fixture_symbols\":[";first=true;
        for(auto x:recovered){if(!first)std::cout<<',';first=false;std::cout<<x;}
        std::cout<<"],\"symbols_checked\":1024,\"worker_threads\":1,\"encrypted_execution\":true,\"benchmark\":false,\"bootstrapping\":false,\"process_isolation\":false}\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
