// Parameter-only extension. Preserve all V1 correspondence/timing sources.
#define main frozen_diagonal_correctness_main
#include "diagonal_bsgs.cpp"
#undef main
#include <chrono>
#include <map>
#include <streambuf>
#include <sys/resource.h>

using Clock=std::chrono::steady_clock;
static double elapsed(Clock::time_point start){return std::chrono::duration<double>(Clock::now()-start).count();}
using Times=std::map<std::string,double>;
struct Timer {
    Times& times;std::string name;Clock::time_point start=Clock::now();
    Timer(Times& t,std::string n):times(t),name(std::move(n)){}
    ~Timer(){times[name]+=elapsed(start);}
};
struct CountBuffer:std::streambuf {
    uint64_t bytes=0;
    std::streamsize xsputn(const char*,std::streamsize n)override{bytes+=uint64_t(n);return n;}
    int overflow(int c)override{if(c!=traits_type::eof())++bytes;return traits_type::not_eof(c);}
};
template<class T> static uint64_t serialized_size(const T& value){CountBuffer buf;std::ostream out(&buf);value.writeTo(out);require(bool(out),"Serializer failed");return buf.bytes;}
static void print_times(const Times& times){bool first=true;std::cout<<'{';for(const auto& [k,v]:times){if(!first)std::cout<<',';first=false;std::cout<<'"'<<k<<"\":"<<v;}std::cout<<'}';}
struct Batch {
    Times times;double wall=0;uint64_t input_bytes=0,output_bytes=0;
    unsigned encryptions=0;std::vector<uint16_t> recovered;
    std::vector<long> output_prime_counts;double min_capacity=1e9;
};

struct Carrier { long m,eta,gamma,dimension,slots,jobs; };
static Carrier carrier(long m){
    if(m==4369)return {4369,258,4115,4096,256,1};
    if(m==13107)return {13107,4627,12853,8192,512,2};
    require(m==21845,"Unlisted carrier");return {21845,8996,21591,16384,1024,4};
}
static unsigned position(const Carrier& c,unsigned q,unsigned j){return unsigned(16*c.jobs)*(j/16)+16*q+j%16;}
static void print_primes(const helib::Context& c,const helib::IndexSet& set){
    bool first=true;std::cout<<'[';for(long i:set){if(!first)std::cout<<',';first=false;std::cout<<'"'<<c.ithPrime(i)<<'"';}std::cout<<']';
}
static void print_profile(const Carrier& p,long bits,const helib::Context& c){
    std::cout<<"{\"m\":"<<p.m<<",\"dimension\":"<<p.dimension<<",\"slots\":"<<p.slots
        <<",\"jobs_per_bundle\":"<<p.jobs<<",\"length\":256,\"generators\":["<<p.eta<<','<<p.gamma
        <<"],\"orders\":[16,"<<16*p.jobs<<"],\"requested_bits\":"<<bits<<",\"requested_digits\":2"
        <<",\"actual_digits\":"<<c.getDigits().size()<<",\"digit_prime_counts\":[";
    bool first=true;for(const auto& d:c.getDigits()){require(d.card()>0,"Empty gadget digit");if(!first)std::cout<<',';first=false;std::cout<<d.card();}
    std::cout<<"],\"sk_hwt\":0,\"field_polynomial\":\"0x1100b\",\"library_security_estimate_NOT_CERTIFICATION\":"<<c.securityLevel()
        <<",\"ciphertext_primes\":";print_primes(c,c.getCtxtPrimes());
    std::cout<<",\"special_primes\":";print_primes(c,c.getSpecialPrimes());std::cout<<'}';
}
static void public_layout(const Carrier& p,const helib::Context& c,const helib::EncryptedArray& ea,bool substitutions){
    const auto& z=c.getZMStar();require(c.getPhiM()==p.dimension&&ea.size()==p.slots&&ea.getDegree()==16,"Wrong full field");
    require(z.numOfGens()==2&&z.OrderOf(0)==16&&z.OrderOf(1)==16*p.jobs&&z.SameOrd(0),"Wrong axes");
    require(z.ZmStarGen(0)==p.eta&&z.ZmStarGen(1)==p.gamma,"Wrong generators");
    std::set<long> units;
    for(unsigned q=0;q<unsigned(p.jobs);++q)for(unsigned j=0;j<256;++j){
        const long i=position(p,q,j),h=j/16,a=16*q+j%16;
        require(z.coordinate(0,i)==h&&z.coordinate(1,i)==a,"Wrong coordinates");
        long rep=NTL::MulMod(NTL::PowerMod(p.eta,h,p.m),NTL::PowerMod(p.gamma,a,p.m),p.m);
        require(z.ith_rep(i)==rep,"Wrong representative");
        for(unsigned k=0;k<16;++k){require(units.insert(rep).second,"Repeated coset");rep=NTL::MulMod(rep,2,p.m);}
    }
    require(units.size()==unsigned(p.dimension),"Incomplete unit cover");
    if(!substitutions)return;
    const auto in=fixture::inputs();std::vector<NTL::ZZX> slots(p.slots),decoded;
    for(unsigned q=0;q<unsigned(p.jobs);++q)for(unsigned j=0;j<256;++j)slots[position(p,q,j)]=polynomial(in.f[q][j]);
    NTL::ZZX encoded;ea.encode(encoded,slots);ea.decode(decoded,encoded);require(decoded==slots,"Codec mismatch");
    NTL::GF2X phi,a;NTL::conv(phi,z.getPhimX());NTL::conv(a,encoded);NTL::GF2XModulus modulus(phi);
    for(unsigned v=1;v<16;++v){
        const long k=z.genToPow(0,-long(v));NTL::GF2X xk,mapped;NTL::PowerXMod(xk,k,modulus);NTL::CompMod(mapped,a,xk,modulus);
        NTL::ZZX transformed;NTL::conv(transformed,mapped);ea.decode(decoded,transformed);
        for(unsigned q=0;q<unsigned(p.jobs);++q)for(unsigned j=0;j<256;++j)
            require(decoded[position(p,q,j)]==slots[position(p,q,(j+16*v)%256)],"Full-field rotation mismatch");
    }
}
struct ProfileBatch:Batch { std::vector<helib::IndexSet> output_prime_sets; };
static ProfileBatch profile_batch(const Carrier& p,const std::string& arm,const fixture::Inputs& in,
    const helib::Context& context,const helib::EncryptedArray& ea,const helib::PubKey& pk,const helib::SecKey& sk){
    ProfileBatch out;const auto start=Clock::now();out.recovered.reserve(4096);
    auto encrypt=[&](const std::vector<NTL::ZZX>& slots){
        NTL::ZZX plain;{Timer t(out.times,"codec");ea.encode(plain,slots);}
        helib::Ctxt ct(pk);{Timer t(out.times,"encryption");pk.Encrypt(ct,plain,2);}
        {Timer t(out.times,"serialization");out.input_bytes+=serialized_size(ct);}++out.encryptions;return ct;
    };
    for(unsigned block=0;block<16/unsigned(p.jobs);++block){
        std::unique_ptr<helib::Ctxt> result;
        if(arm=="b16"){
            std::vector<helib::Ctxt> babies;babies.reserve(16);
            for(unsigned r=0;r<16;++r){std::vector<NTL::ZZX> f;
                {Timer t(out.times,"owner_f");f.resize(p.slots);
                    for(unsigned q=0;q<unsigned(p.jobs);++q)for(unsigned j=0;j<256;++j)
                        f[position(p,q,j)]=polynomial(in.f[p.jobs*block+q][(j+r)%256]);}
                babies.push_back(encrypt(f));}
            std::vector<std::array<fixture::Jet,256>> columns;
            {Timer t(out.times,"owner_g");columns.resize(p.jobs);for(unsigned q=0;q<unsigned(p.jobs);++q){columns[q][0][0]=1;
                for(unsigned i=1;i<256;++i)columns[q][i]=fixture::series_product(columns[q][i-1],in.g[p.jobs*block+q]);}}
            PublicBSGS evaluator(babies,ea);
            for(unsigned h=0;h<256;h+=16){for(unsigned r=0;r<16;++r){if(h+r==1)continue;
                    std::vector<NTL::ZZX> diagonal;
                    {Timer t(out.times,"owner_g");diagonal.resize(p.slots);
                        for(unsigned q=0;q<unsigned(p.jobs);++q)for(unsigned j=0;j<256;++j){
                            const unsigned y=(j+256-h)%256,i=(j+r)%256;
                            diagonal[position(p,q,j)]=polynomial(columns[q][i][y]);}}
                    auto d=encrypt(diagonal);{Timer t(out.times,"evaluation");evaluator.consume(r,d);}}
                {Timer t(out.times,"evaluation");evaluator.finish_group();}}
            {Timer t(out.times,"evaluation");result=std::make_unique<helib::Ctxt>(evaluator.finish());}
        }else{
            std::vector<NTL::ZZX> constant;
            {Timer t(out.times,"owner_f");constant.resize(p.slots);for(unsigned q=0;q<unsigned(p.jobs);++q)
                constant[position(p,q,0)]=polynomial(in.f[p.jobs*block+q][0]);}
            result=std::make_unique<helib::Ctxt>(encrypt(constant));
            std::vector<fixture::Jet> powers(p.jobs);for(auto& x:powers)x[0]=1;
            for(unsigned i=1;i<256;++i){std::vector<NTL::ZZX> f,a;
                {Timer t(out.times,"owner_f");f.resize(p.slots);for(unsigned q=0;q<unsigned(p.jobs);++q)for(unsigned j=0;j<256;++j)
                    f[position(p,q,j)]=polynomial(in.f[p.jobs*block+q][i]);}
                {Timer t(out.times,"owner_g");a.resize(p.slots);for(unsigned q=0;q<unsigned(p.jobs);++q){
                    powers[q]=fixture::series_product(powers[q],in.g[p.jobs*block+q]);
                    for(unsigned j=0;j<256;++j)a[position(p,q,j)]=polynomial(powers[q][j]);}}
                auto cf=encrypt(f),ca=encrypt(a);
                {Timer t(out.times,"evaluation");require(cf.inCanonicalForm()&&ca.inCanonicalForm(),"Nonfresh input");cf.multLowLvl(ca);
                    require(!cf.inCanonicalForm(),"Implicit relin");*result+=cf;}}
            {Timer t(out.times,"evaluation");result->reLinearize();require(result->inCanonicalForm(),"Noncanonical output");}
        }
        {Timer t(out.times,"evaluation");result->modDownToSet(result->getPrimeSet()&context.getCtxtPrimes());}
        const double capacity=result->bitCapacity();out.min_capacity=std::min(out.min_capacity,capacity);
        if(capacity<10){std::cout<<"{\"event\":\"capacity_rejection\",\"bundle\":"<<block<<",\"capacity\":"<<capacity<<"}\n"<<std::flush;
            throw std::runtime_error("Output capacity below predeclared ten-bit margin");}
        require((result->getPrimeSet()&context.getSpecialPrimes()).card()==0,"Special output prime remains");
        out.output_prime_sets.push_back(result->getPrimeSet());out.output_prime_counts.push_back(result->getPrimeSet().card());
        {Timer t(out.times,"serialization");out.output_bytes+=serialized_size(*result);}
        {Timer t(out.times,"decryption_codec");NTL::ZZX plain;sk.Decrypt(plain,*result);std::vector<NTL::ZZX> decoded;ea.decode(decoded,plain);
            for(unsigned q=0;q<unsigned(p.jobs);++q)for(unsigned j=0;j<256;++j)out.recovered.push_back(symbol(decoded[position(p,q,j)]));}
    }
    require(out.encryptions==(arm=="b16"?271u:511u)*(16/unsigned(p.jobs)),"Wrong input count");out.wall=elapsed(start);return out;
}
int main(int argc,char** argv){
    try{
        require(argc==5,"Use V2 supervisor");const std::string mode=argv[1],arm=argv[2];
        require(mode=="public"||mode=="gate"||mode=="sample","Unknown mode");
        require(arm=="column"||arm=="b16","Unknown arm");const Carrier p=carrier(std::stol(argv[3]));const long bits=std::stol(argv[4]);
        require(bits==20||bits==60,"Unlisted bit request");NTL::SetNumThreads(1);const auto start=Clock::now();Times setup;
        std::unique_ptr<helib::Context> context;std::unique_ptr<helib::EncryptedArray> ea;
        {Timer t(setup,"public_context_codec");context.reset(new helib::Context(helib::ContextBuilder<helib::BGV>().m(p.m).p(2).r(1)
            .gens({p.eta,p.gamma}).ords({16,16*p.jobs}).bits(bits).c(2).skHwt(0).bootstrappable(false).build()));
            NTL::ZZX G;for(long j:{0L,1L,3L,12L,16L})NTL::SetCoeff(G,j,1);ea=std::make_unique<helib::EncryptedArray>(*context,G);}
        public_layout(p,*context,*ea,mode=="public");std::cout<<std::setprecision(17);
        if(mode=="public"){
            std::cout<<"{\"status\":\"SLACK_PUBLIC_PASS\",\"profile\":";print_profile(p,bits,*context);
            std::cout<<",\"units_checked\":"<<p.dimension<<",\"polynomial_automorphisms_checked\":15,\"rotated_field_symbols_checked\":"<<15*p.slots
                <<",\"keys_generated\":0,\"encrypted_execution\":false,\"security_certified\":false}\n";return 0;}
        require(context->securityLevel()>=128,"Fails preliminary library filter");
        require(!helib::isSetAutomorphVals()&&!helib::isSetAutomorphVals2(),"Automorphism execution disabled");
        std::unique_ptr<helib::SecKey> sk;std::unique_ptr<helib::PubKey> pk;
        {Timer t(setup,"keys_hints");std::array<unsigned char,32> entropy{};
            {std::ifstream source("/dev/urandom",std::ios::binary);require(bool(source.read(reinterpret_cast<char*>(entropy.data()),entropy.size())),"OS entropy unavailable");}
            NTL::SetSeed(NTL::ZZFromBytes(entropy.data(),entropy.size()));entropy.fill(0);
            sk=std::make_unique<helib::SecKey>(*context);sk->GenSecKey(2,2);
            if(arm=="b16"){std::set<long> autos;for(unsigned v=1;v<16;++v)autos.insert(context->getZMStar().genToPow(0,-long(v)));helib::addTheseMatrices(*sk,autos);}
            pk=std::make_unique<helib::PubKey>(*sk);}
        require(typeid(*pk)==typeid(helib::PubKey)&&pk->keySWlist().size()==(arm=="b16"?16u:1u),"Wrong public keys");
        if(arm=="b16")for(unsigned v=1;v<16;++v){const long k=context->getZMStar().genToPow(0,-long(v));
            require(pk->getNextKSWmatrix(k,0).fromKey.getPowerOfX()==k,"Multihop rotation");}
        uint64_t key_bytes;{Timer t(setup,"public_key_serialization");key_bytes=serialized_size(*pk);}
        std::cout<<"{\"event\":\"slack_setup_complete\",\"profile\":";print_profile(p,bits,*context);std::cout<<"}\n"<<std::flush;
        const auto in=fixture::inputs();std::vector<uint16_t> expected;for(unsigned q=0;q<16;++q){auto v=fixture::horner(in.f[q],in.g[q]);expected.insert(expected.end(),v.begin(),v.end());}
        std::vector<ProfileBatch> batches;
        for(unsigned index=0;index<(mode=="gate"?1u:2u);++index){auto b=profile_batch(p,arm,in,*context,*ea,*pk,*sk);
            {Timer t(b.times,"verification");require(b.recovered==expected,"Output differs from independent Horner");}batches.push_back(std::move(b));
            std::cout<<"{\"event\":\"slack_batch_complete\",\"index\":"<<index<<"}\n"<<std::flush;}
        struct rusage usage{};getrusage(RUSAGE_SELF,&usage);
        std::cout<<"{\"status\":\"SLACK_"<<(mode=="gate"?"GATE":"SAMPLE")<<"_PASS\",\"arm\":\""<<arm<<"\",\"setup_seconds\":";print_times(setup);
        std::cout<<",\"public_key_including_hints_bytes_serialized\":"<<key_bytes<<",\"peak_rss_kib\":"<<usage.ru_maxrss
            <<",\"process_wall_seconds\":"<<elapsed(start)<<",\"worker_threads\":1,\"batches\":[";
        for(unsigned i=0;i<batches.size();++i){const auto& b=batches[i];if(i)std::cout<<',';
            std::cout<<"{\"index\":"<<i<<",\"state\":\""<<(i?"warm":"cold")<<"\",\"seconds\":";print_times(b.times);
            std::cout<<",\"batch_wall_seconds\":"<<b.wall<<",\"input_bytes_serialized\":"<<b.input_bytes<<",\"output_bytes_serialized\":"<<b.output_bytes
                <<",\"fresh_encryptions\":"<<b.encryptions<<",\"output_symbols\":4096,\"minimum_output_bit_capacity\":"<<b.min_capacity<<",\"output_prime_sets\":[";
            for(unsigned j=0;j<b.output_prime_sets.size();++j){if(j)std::cout<<',';print_primes(*context,b.output_prime_sets[j]);}
            std::cout<<"],\"recovered_public_fixture_symbols\":[";for(unsigned j=0;j<b.recovered.size();++j){if(j)std::cout<<',';std::cout<<b.recovered[j];}std::cout<<"]}";}
        std::cout<<"],\"profile\":";print_profile(p,bits,*context);
        std::cout<<",\"matched_jobs\":16,\"fixture_fnv64\":\""<<fixture::checksum(in)<<"\",\"process_isolation\":false,\"security_certified\":false,\"bootstrapping\":false}\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
