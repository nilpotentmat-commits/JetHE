// Reuse frozen correspondence routines; do not alter their receipts.
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
static Batch batch(const std::string& arm,const fixture::Inputs& in,
    const helib::Context& context,const helib::EncryptedArray& ea,
    const helib::PubKey& pk,const helib::SecKey& sk){
    Batch out;const auto start=Clock::now();out.recovered.reserve(4096);
    auto encrypt=[&](const std::vector<NTL::ZZX>& slots){
        NTL::ZZX plain;{Timer t(out.times,"codec");ea.encode(plain,slots);}
        helib::Ctxt ct(pk);{Timer t(out.times,"encryption");pk.Encrypt(ct,plain,2);}
        {Timer t(out.times,"serialization");out.input_bytes+=serialized_size(ct);}
        ++out.encryptions;return ct;
    };
    for(unsigned block=0;block<4;++block){
        std::unique_ptr<helib::Ctxt> result;
        if(arm=="b16"){
            std::vector<helib::Ctxt> babies;babies.reserve(16);
            for(unsigned r=0;r<16;++r){
                std::vector<NTL::ZZX> f;
                {Timer t(out.times,"owner_f");f.resize(1024);
                    for(unsigned q=0;q<4;++q)for(unsigned j=0;j<256;++j)f[slot(q,j)]=polynomial(in.f[4*block+q][(j+r)%256]);}
                babies.push_back(encrypt(f));
            }
            std::array<std::array<fixture::Jet,256>,4> columns{};
            {Timer t(out.times,"owner_g");for(unsigned q=0;q<4;++q){columns[q][0][0]=1;
                for(unsigned i=1;i<256;++i)columns[q][i]=fixture::series_product(columns[q][i-1],in.g[4*block+q]);}}
            PublicBSGS evaluator(babies,ea);
            for(unsigned h=0;h<256;h+=16){
                for(unsigned r=0;r<16;++r){
                    if(h+r==1)continue;
                    std::vector<NTL::ZZX> diagonal;
                    {Timer t(out.times,"owner_g");diagonal.resize(1024);
                        for(unsigned q=0;q<4;++q)for(unsigned j=0;j<256;++j){
                            unsigned y=(j+256-h)%256,i=(j+r)%256;
                            diagonal[slot(q,j)]=polynomial(columns[q][i][y]);}}
                    auto d=encrypt(diagonal);{Timer t(out.times,"evaluation");evaluator.consume(r,d);}
                }
                {Timer t(out.times,"evaluation");evaluator.finish_group();}
            }
            {Timer t(out.times,"evaluation");result=std::make_unique<helib::Ctxt>(evaluator.finish());}
        }else{
            std::vector<NTL::ZZX> constant;
            {Timer t(out.times,"owner_f");constant.resize(1024);
                for(unsigned q=0;q<4;++q)constant[slot(q,0)]=polynomial(in.f[4*block+q][0]);}
            result=std::make_unique<helib::Ctxt>(encrypt(constant));
            std::array<fixture::Jet,4> powers{};for(auto& p:powers)p[0]=1;
            for(unsigned i=1;i<256;++i){
                std::vector<NTL::ZZX> f,a;
                {Timer t(out.times,"owner_f");f.resize(1024);
                    for(unsigned q=0;q<4;++q)for(unsigned j=0;j<256;++j)f[slot(q,j)]=polynomial(in.f[4*block+q][i]);}
                {Timer t(out.times,"owner_g");a.resize(1024);
                    for(unsigned q=0;q<4;++q){powers[q]=fixture::series_product(powers[q],in.g[4*block+q]);
                        for(unsigned j=0;j<256;++j)a[slot(q,j)]=polynomial(powers[q][j]);}}
                auto cf=encrypt(f),ca=encrypt(a);
                {Timer t(out.times,"evaluation");require(cf.inCanonicalForm()&&ca.inCanonicalForm(),"Nonfresh column input");
                    cf.multLowLvl(ca);require(!cf.inCanonicalForm(),"Unexpected column relin");*result+=cf;}
            }
            {Timer t(out.times,"evaluation");result->reLinearize();require(result->inCanonicalForm(),"Noncanonical column output");}
        }
        {Timer t(out.times,"evaluation");
            result->modDownToSet(result->getPrimeSet()&context.getCtxtPrimes());}
        out.min_capacity=std::min(out.min_capacity,double(result->bitCapacity()));
        require(result->bitCapacity()>0,"No output capacity");
        require((result->getPrimeSet()&context.getSpecialPrimes()).card()==0,"Special output primes remain");
        out.output_prime_counts.push_back(result->getPrimeSet().card());
        {Timer t(out.times,"serialization");out.output_bytes+=serialized_size(*result);}
        {Timer t(out.times,"decryption_codec");NTL::ZZX plain;sk.Decrypt(plain,*result);
            std::vector<NTL::ZZX> decoded;ea.decode(decoded,plain);
            for(unsigned q=0;q<4;++q)for(unsigned j=0;j<256;++j)out.recovered.push_back(symbol(decoded[slot(q,j)]));}
    }
    require(out.encryptions==(arm=="b16"?1084u:2044u),"Wrong sixteen-job input count");
    out.wall=elapsed(start);return out;
}

int main(int argc,char** argv){
    try{
        require(argc==3&&std::string(argv[1])=="--screen-v1","Use screen supervisor");
        const std::string arm=argv[2];require(arm=="column"||arm=="b16","Unknown arm");
        const auto process_start=Clock::now();NTL::SetNumThreads(1);Times setup;
        const auto in=fixture::inputs();
        std::unique_ptr<helib::Context> context;std::unique_ptr<helib::EncryptedArray> ea;
        {Timer t(setup,"public_context_codec");
            context.reset(new helib::Context(helib::ContextBuilder<helib::BGV>().m(M).p(2).r(1)
                .gens({ETA,GAMMA}).ords({16,64}).bits(120).c(2).skHwt(0).bootstrappable(false).build()));
            NTL::ZZX G;for(long j:{0L,1L,3L,12L,16L})NTL::SetCoeff(G,j,1);
            ea=std::make_unique<helib::EncryptedArray>(*context,G);}
        require(context->securityLevel()>=128,"Fails preliminary heuristic filter");layout_check(*context,*ea);
        require(!helib::isSetAutomorphVals()&&!helib::isSetAutomorphVals2(),"Automorphism execution disabled");
        std::unique_ptr<helib::SecKey> sk;std::unique_ptr<helib::PubKey> pk;
        {Timer t(setup,"keys_hints");std::array<unsigned char,32> entropy{};
            {std::ifstream source("/dev/urandom",std::ios::binary);require(bool(source.read(reinterpret_cast<char*>(entropy.data()),entropy.size())),"OS entropy unavailable");}
            NTL::SetSeed(NTL::ZZFromBytes(entropy.data(),entropy.size()));entropy.fill(0);
            sk=std::make_unique<helib::SecKey>(*context);sk->GenSecKey(2,2);
            if(arm=="b16"){std::set<long> autos;for(unsigned v=1;v<16;++v)autos.insert(context->getZMStar().genToPow(0,-long(v)));
                helib::addTheseMatrices(*sk,autos);}
            pk=std::make_unique<helib::PubKey>(*sk);}
        require(typeid(*pk)==typeid(helib::PubKey)&&pk->keySWlist().size()==(arm=="b16"?16u:1u),"Wrong public keys");
        if(arm=="b16")for(unsigned v=1;v<16;++v){const long k=context->getZMStar().genToPow(0,-long(v));
            require(pk->getNextKSWmatrix(k,0).fromKey.getPowerOfX()==k,"Unexpected multihop rotation");}
        uint64_t key_bytes;{Timer t(setup,"public_key_serialization");key_bytes=serialized_size(*pk);}
        std::cout<<"{\"event\":\"helib_measurement_setup_complete\",\"arm\":\""<<arm<<"\"}\n"<<std::flush;
        std::vector<uint16_t> expected;for(unsigned q=0;q<16;++q){const auto v=fixture::horner(in.f[q],in.g[q]);expected.insert(expected.end(),v.begin(),v.end());}
        std::vector<Batch> batches;
        for(unsigned index=0;index<2;++index){auto b=batch(arm,in,*context,*ea,*pk,*sk);
            {Timer t(b.times,"verification");require(b.recovered==expected,"Matched batch differs from Horner");}
            batches.push_back(std::move(b));
            std::cout<<"{\"event\":\"helib_measurement_batch_complete\",\"arm\":\""<<arm<<"\",\"index\":"<<index<<"}\n"<<std::flush;}
        struct rusage usage{};getrusage(RUSAGE_SELF,&usage);
        std::cout<<std::setprecision(17)<<"{\"status\":\"MATCHED_SCREEN_HELIB_PASS\",\"arm\":\""<<arm<<"\",\"setup_seconds\":";print_times(setup);
        std::cout<<",\"public_key_including_hints_bytes_serialized\":"<<key_bytes<<",\"peak_rss_kib\":"<<usage.ru_maxrss
            <<",\"process_wall_seconds\":"<<elapsed(process_start)<<",\"worker_threads\":1,\"batches\":[";
        for(unsigned i=0;i<batches.size();++i){const auto& b=batches[i];if(i)std::cout<<',';
            std::cout<<"{\"index\":"<<i<<",\"state\":\""<<(i?"warm":"cold")<<"\",\"seconds\":";print_times(b.times);
            std::cout<<",\"batch_wall_seconds\":"<<b.wall<<",\"input_bytes_serialized\":"<<b.input_bytes<<",\"output_bytes_serialized\":"<<b.output_bytes
                <<",\"fresh_encryptions\":"<<b.encryptions<<",\"output_symbols\":4096,\"minimum_output_bit_capacity\":"<<b.min_capacity<<",\"output_prime_counts\":[";
            for(unsigned j=0;j<b.output_prime_counts.size();++j){if(j)std::cout<<',';std::cout<<b.output_prime_counts[j];}
            std::cout<<"],\"recovered_public_fixture_symbols\":[";
            for(unsigned j=0;j<b.recovered.size();++j){if(j)std::cout<<',';std::cout<<b.recovered[j];}std::cout<<"]}";}
        std::cout<<"],\"profile\":{";profile(*context);
        std::cout<<"},\"matched_jobs\":16,\"fixture_fnv64\":\""<<fixture::checksum(in)<<"\",\"process_isolation\":false,\"security_certified\":false,\"bootstrapping\":false}\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
