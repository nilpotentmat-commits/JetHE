// Matched timing: reuse frozen arithmetic and add whole-evaluator accounting.
#define main frozen_functional_driver_main
#include "terminal_core_v3.cpp"
#undef main
#include <type_traits>

template<class F> auto evaluated(Ledger& ledger,double& total,F&& f) {
  const double validation=ledger.times["validation"];
  const auto begin=Clock::now();
  if constexpr(std::is_void_v<std::invoke_result_t<F>>) {
    f(); total+=std::chrono::duration<double>(Clock::now()-begin).count()-(ledger.times["validation"]-validation);
  } else {
    auto result=f();
    total+=std::chrono::duration<double>(Clock::now()-begin).count()-(ledger.times["validation"]-validation);
    return result;
  }
}

static Json measured_batch(const core::Cell& c,const std::string& arm,const Policy& p,
  const core::Field& field,const core::AdditiveCRT& codec,const std::vector<Words>& in,const Words& expected,
  const helib::Context& ctx,const helib::EncryptedArray& ea,const helib::PubKey& pk,const helib::SecKey& sk) {
  Ledger ledger; Times* times=&ledger.times; Evaluator eval(ctx,ledger,true);
  double evaluation_total=0; uint64_t prepared_bytes=0;
  const auto started=Clock::now();
  Words recovered; Json outputs=Json::array(); bool all_match=true; unsigned slot_checks=0;
  if(arm=="crt") {
    std::vector<Words> prepared;
    { Timer t(times,"owner_preparation"); prepared=core::prepare(c,codec,in); }
    for(const auto& owner:prepared) prepared_bytes+=2*owner.size();
    const unsigned total=c.jobs*codec.size,S=unsigned(ea.size()),groups=(total+S-1)/S;
    Words terminal(total);
    for(unsigned group=0;group<groups;++group) {
      std::vector<helib::Ctxt> encrypted; encrypted.reserve(in.size());
      for(const auto& owner:prepared) {
        Words values;
        { Timer t(times,"owner_packing"); values.resize(S);
          const unsigned begin=group*S,count=std::min(S,total-begin);
          std::copy_n(owner.begin()+begin,count,values.begin()); }
        encrypted.push_back(encrypt_slots(values,ea,pk,ledger,true));
      }
      auto result=evaluated(ledger,evaluation_total,[&]{ return eval.primary(std::move(encrypted),c,p,group); });
      const auto values=decrypt_slots(result,sk,ea,ledger,true);
      { Timer t(times,"recipient_decoding");
        std::copy_n(values.begin(),std::min(S,total-group*S),terminal.begin()+group*S); }
      { Timer t(times,"validation");
        for(unsigned j=0;j<S;++j) {
          const unsigned i=group*S+j; uint16_t want=0;
          if(i<total) {
            if(c.family==1) want=field.mul(prepared[0][i],prepared[1][i]);
            else { std::array<uint16_t,4> terms{};
              for(unsigned k=0;k<(c.family==3?4u:1u);++k)
                terms[k]=field.mul(prepared[3*k][i],prepared[3*k+1][i])^prepared[3*k+2][i];
              want=c.family==2?terms[0]:field.mul(field.mul(terms[0],terms[1]),field.mul(terms[2],terms[3])); }
          }
          all_match&=values[j]==want; ++slot_checks;
        }
        outputs.push_back({{"group",group},{"parts",p.terminal_parts},{"prime_indices",indices(result.getPrimeSet())},
          {"bit_capacity",result.bitCapacity()},{"library_is_correct",result.isCorrect()}});
      }
    }
    for(unsigned job=0;job<c.jobs;++job) {
      Words coeff;
      { Timer t(times,"recipient_interpolation");
        coeff=codec.inverse(Words(terminal.begin()+job*codec.size,terminal.begin()+(job+1)*codec.size));
        recovered.insert(recovered.end(),coeff.begin(),coeff.begin()+c.length); }
      { Timer t(times,"validation"); for(unsigned j=c.degree()+1;j<codec.size;++j) all_match&=coeff[j]==0; }
    }
  } else {
    require(ea.size()==512&&c.length==256&&c.jobs==16,"BSGS timing profile mismatch");
    // A prepared diagonal is streamed. The sixteen babies retained below are
    // ciphertexts, not a cached plaintext input supplied for free by an owner.
    prepared_bytes=2*512;
    for(unsigned block=0;block<8;++block) {
      std::vector<helib::Ctxt> babies; babies.reserve(16);
      for(unsigned r=0;r<16;++r) {
        Words values;
        { Timer t(times,"owner_preparation"); values.resize(512);
          for(unsigned q=0;q<2;++q) for(unsigned j=0;j<256;++j)
            values[slot(q,j)]=in[0][256*(2*block+q)+(j+r)%256]; }
        babies.push_back(encrypt_slots(values,ea,pk,ledger,true));
      }
      std::unique_ptr<helib::Ctxt> raw,canonical;
      for(unsigned v=0;v<16;++v) {
        std::unique_ptr<helib::Ctxt> sum;
        for(unsigned r=0;r<16;++r) {
          Words values;
          { Timer t(times,"owner_preparation"); values.resize(512);
            for(unsigned q=0;q<2;++q) for(unsigned j=0;j<256;++j) {
              const unsigned y=(j+256-16*v)%256,i=(j+r)%256;
              values[slot(q,j)]=i<=y?in[1][256*(2*block+q)+y-i]:0;
            } }
          auto diagonal=encrypt_slots(values,ea,pk,ledger,true);
          evaluated(ledger,evaluation_total,[&] {
            helib::Ctxt value=babies[r]; eval.mul(value,diagonal,2,2);
            if(sum) eval.add(*sum,std::move(value)); else sum=std::make_unique<helib::Ctxt>(std::move(value));
          });
        }
        evaluated(ledger,evaluation_total,[&] {
          eval.observe(*sum,3,block,"bsgs_group_raw");
          if(v==0) raw=std::move(sum);
          else {
            eval.relin(*sum,3); eval.rotate(*sum,ea,v); eval.observe(*sum,2,block,"bsgs_group_rotated");
            if(canonical) eval.add(*canonical,std::move(*sum)); else canonical=std::move(sum);
          }
        });
      }
      evaluated(ledger,evaluation_total,[&] {
        require(raw&&canonical,"Incomplete BSGS groups");
        eval.normalize(*raw); eval.normalize(*canonical); eval.add(*raw,std::move(*canonical));
        eval.observe(*raw,3,block,"terminal");
      });
      const auto values=decrypt_slots(*raw,sk,ea,ledger,true);
      { Timer t(times,"recipient_decoding");
        for(unsigned q=0;q<2;++q) for(unsigned j=0;j<256;++j) recovered.push_back(values[slot(q,j)]); }
      { Timer t(times,"validation"); slot_checks+=512;
        outputs.push_back({{"group",block},{"parts",3},{"prime_indices",indices(raw->getPrimeSet())},
          {"bit_capacity",raw->bitCapacity()},{"library_is_correct",raw->isCorrect()}}); }
    }
  }
  bool margin=true;
  { Timer t(times,"validation");
    all_match&=recovered==expected;
    for(const auto& row:outputs) margin&=row.at("bit_capacity").get<double>()>=10&&row.at("library_is_correct").get<bool>();
  }
  const double elapsed=std::chrono::duration<double>(Clock::now()-started).count();
  const double local=elapsed-ledger.times["validation"];
  double attributed=evaluation_total;
  Times phases={{"evaluation_total",evaluation_total}},kernels;
  for(const auto& row:ledger.times) {
    if(row.first.rfind("evaluation_",0)==0) kernels[row.first]=row.second;
    else { phases[row.first]=row.second; if(row.first!="validation") attributed+=row.second; }
  }
  require(local>=attributed&&evaluation_total>0,"Overlapping matched phase timers");
  Json result=ledger.json(); result["output_profiles"]=outputs; result["recovered_public_fixture_symbols"]=recovered;
  result["all_outputs_match"]=all_match; result["terminal_slots_checked"]=slot_checks;
  result["terminal_capacity_gate"]=margin; result["functional_admitted"]=all_match&&margin&&ledger.all_library_correct;
  result["seconds"]=phases; result["kernel_seconds"]=kernels; result["batch_wall_seconds"]=elapsed;
  result["local_compute_seconds"]=local; result["unallocated_charged_seconds"]=local-attributed;
  result["prepared_plaintext_cache_bytes"]=prepared_bytes;
  return result;
}

int main(int argc,char** argv) {
  try {
    helib::helog.setLogToStderr(); NTL::SetNumThreads(1);
    require(argc==7&&std::string(argv[1])=="sample","Use matched supervisor only");
    const std::string arm=argv[2]; const auto c=core::cell(argv[3]);
    const long m=std::stol(argv[4]),bits=std::stol(argv[5]); const auto p=policy(c,arm,argv[6]);
    require(m==4369||m==13107||m==21845||m==65535,"Unlisted timing conductor");
    require(bits==20||bits==60||bits==120||bits==180||bits==240,"Unlisted timing request");
    require(arm!="b16"||m==13107,"Unproved timing layout");
    Times setup; std::unique_ptr<helib::Context> ctx; std::unique_ptr<helib::EncryptedArray> ea;
    std::unique_ptr<core::Field> field; std::unique_ptr<core::AdditiveCRT> codec;
    { Timer t(&setup,"public_setup"); NTL::SetSeed(NTL::ZZ(20260908));
      auto builder=helib::ContextBuilder<helib::BGV>().m(m).p(2).r(1).bits(bits).c(2).skHwt(0).bootstrappable(false);
      if(arm=="b16") builder.gens({4627,12853}).ords({16,32});
      ctx.reset(new helib::Context(builder.build())); NTL::ZZX G;
      for(long j:{0L,1L,3L,12L,16L}) NTL::SetCoeff(G,j,1);
      ea=std::make_unique<helib::EncryptedArray>(*ctx,G);
      field=std::make_unique<core::Field>(); codec=std::make_unique<core::AdditiveCRT>(*field,c.points());
    }
    auto desc=profile(*ctx,*ea,bits,arm);
    double sd=NTL::to_double(ctx->getStdev()); if(ctx->getZMStar().getPow2()==0) sd*=std::sqrt(double(ctx->getM()));
    const double q_only=helib::lweEstimateSecurity(int(ctx->getPhiM()),
      (ctx->logOfProduct(ctx->getCtxtPrimes())-std::log(sd))/std::log(2.0),int(ctx->getHwt()));
    const double effective=p.matrices==0?q_only:ctx->securityLevel();
    desc["published_q_library_heuristic_NOT_CERTIFICATION"]=q_only;
    desc["effective_library_heuristic_NOT_CERTIFICATION"]=effective;
    desc["effective_library_128_screen"]=effective>=128; desc["screen_modulus"]=p.matrices==0?"Q":"QP";
    desc["assumed_switching_matrices"]=p.matrices; desc["adjusted_library_stdev"]=sd;
    require(effective>=128,"Ineligible timing profile");
    require(!helib::isSetAutomorphVals()&&!helib::isSetAutomorphVals2(),"Fake automorphism execution");
    std::unique_ptr<helib::SecKey> sk; std::unique_ptr<helib::PubKey> pk; uint64_t key_bytes=0;
    { Timer t(&setup,"keys_and_serialization"); entropy_seed(); sk=std::make_unique<helib::SecKey>(*ctx);
      require(sk->GenSecKey(2,1)==0,"Wrong timing key id");
      if(p.matrices) sk->GenKeySWmatrix(2,1,0,0,2);
      if(arm=="crt"&&p.matrices==3) for(long s:{3L,4L}) sk->GenKeySWmatrix(s,1,0,0,2);
      if(arm=="b16") { std::set<long> autos;
        for(unsigned v=1;v<16;++v) autos.insert(ctx->getZMStar().genToPow(0,-long(v)));
        helib::addTheseMatrices(*sk,autos);
      }
      pk=std::make_unique<helib::PubKey>(*sk); key_bytes=serialized_size(*pk);
    }
    require(typeid(*pk)==typeid(helib::PubKey)&&pk->keySWlist().size()==p.matrices&&!pk->isBootstrappable(),"Wrong timing public keys");
    Json matrices=Json::array(); std::set<std::pair<long,long>> expected_matrices,actual_matrices;
    if(p.matrices) expected_matrices.insert({2,1});
    if(arm=="crt"&&p.matrices==3) { expected_matrices.insert({3,1}); expected_matrices.insert({4,1}); }
    if(arm=="b16") for(unsigned v=1;v<16;++v) {
      const long k=ctx->getZMStar().genToPow(0,-long(v)); expected_matrices.insert({1,k});
      require(pk->getNextKSWmatrix(k,0).fromKey.getPowerOfX()==k,"Multihop timing rotation");
    }
    for(const auto& matrix:pk->keySWlist()) {
      require(matrix.fromKey.getSecretKeyID()==0&&matrix.toKeyID==0&&matrix.ptxtSpace==2,"Wrong timing key graph");
      actual_matrices.insert({matrix.fromKey.getPowerOfS(),matrix.fromKey.getPowerOfX()});
      matrices.push_back({{"power_of_s",matrix.fromKey.getPowerOfS()},
        {"power_of_x",matrix.fromKey.getPowerOfX()},{"columns",matrix.NumCols()}});
    }
    require(actual_matrices==expected_matrices,"Wrong timing switching inventory");
    const auto in=core::inputs(c); const auto expected=core::oracle(*field,c,in);
    uint64_t input_fnv=14695981039346656037ULL; for(const auto& owner:in) input_fnv=core::fnv(owner,input_fnv);
    std::cout<<Json({{"event","core_matched_setup_complete"},{"profile",desc},{"switching_matrices",matrices}}).dump()<<'\n'<<std::flush;
    Json batches=Json::array(); bool good=true;
    for(unsigned index=0;index<2;++index) {
      auto value=measured_batch(c,arm,p,*field,*codec,in,expected,*ctx,*ea,*pk,*sk);
      value["index"]=index; good&=value.at("functional_admitted").get<bool>(); batches.push_back(std::move(value));
    }
    struct rusage usage{}; getrusage(RUSAGE_SELF,&usage);
    std::cout<<Json({{"status",good?"CORE_MATCHED_PASS":"CORE_MATCHED_REJECT"},
      {"compiler",arm},{"cell",c.name},{"policy",p.name},{"profile",desc},{"switching_matrices",matrices},
      {"fixture_fnv64",std::to_string(input_fnv)},{"setup_seconds",setup},{"batches",batches},
      {"first_use_local_seconds",setup["public_setup"]+setup["keys_and_serialization"]+batches[0].at("local_compute_seconds").get<double>()},
      {"public_key_including_hints_bytes_serialized",key_bytes},{"peak_rss_kib",usage.ru_maxrss},
      {"benchmark",true},{"encrypted_execution",true},{"security_128_qualified",false},{"bootstrapping",false},
      {"process_isolation",false},{"secret_keys_exported",false},{"phase_diagnostics_exported",false},
      {"ciphertext_bodies_exported",false},{"network_transfer_measured",false}}).dump()<<'\n';
    return good?0:2;
  } catch(const NoiseAdmissionReject& e) {
    std::cout<<Json({{"status","CORE_MATCHED_NOISE_REJECT"},{"reason",e.what()},
      {"full_output_verified",false},{"benchmark",true},{"security_128_qualified",false}}).dump()<<'\n'; return 2;
  } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
