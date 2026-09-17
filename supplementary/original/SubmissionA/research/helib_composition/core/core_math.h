// Public GF(2^16), additive CRT and the frozen core-grid-v1 fixture.
// Neither this deterministic generator nor field-table lookups are encryption RNG.
#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace core {
using Words = std::vector<uint16_t>;
inline void require(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
inline uint16_t slow_mul(unsigned a, unsigned b) {
  unsigned out=0;
  while (b) { if (b&1) out^=a; b>>=1; a<<=1; if(a&65536) a^=0x1100b; }
  return uint16_t(out);
}
inline uint16_t slow_power(uint16_t a, unsigned n) {
  uint16_t out=1;
  while(n) { if(n&1) out=slow_mul(out,a); a=slow_mul(a,a); n>>=1; }
  return out;
}
struct Field {
  std::array<uint16_t,65536> logs{};
  std::array<uint16_t,131070> exponents{};
  Field() {
    unsigned generator=2;
    for(;generator<50;++generator) {
      bool primitive=true;
      for(unsigned p:{3u,5u,17u,257u}) primitive&=slow_power(uint16_t(generator),65535/p)!=1;
      if(primitive) break;
    }
    require(generator<50,"No primitive field generator");
    std::array<bool,65536> seen{}; uint16_t x=1;
    for(unsigned i=0;i<65535;++i) {
      require(x&&!seen[x],"Field table cycle"); seen[x]=true; logs[x]=uint16_t(i);
      exponents[i]=exponents[i+65535]=x; x=slow_mul(x,generator);
    }
    require(x==1,"Field generator order");
  }
  uint16_t mul(uint16_t a,uint16_t b) const {
    return a&&b ? exponents[unsigned(logs[a])+logs[b]] : 0;
  }
  uint16_t power(uint16_t a,unsigned n) const {
    uint16_t out=1;
    while(n) { if(n&1) out=mul(out,a); a=mul(a,a); n>>=1; }
    return out;
  }
};
inline uint64_t fnv(const Words& a, uint64_t h=14695981039346656037ULL) {
  for(uint16_t x:a) for(unsigned shift:{0u,8u}) { h^=(x>>shift)&255; h*=1099511628211ULL; }
  return h;
}
inline uint16_t draw(uint64_t& state) {
  state+=0x9E3779B97F4A7C15ULL; uint64_t z=state;
  z=(z^(z>>30))*0xBF58476D1CE4E5B9ULL;
  z=(z^(z>>27))*0x94D049BB133111EBULL;
  return uint16_t(z^(z>>31));
}
struct Cell {
  std::string name; unsigned family,length,jobs;
  unsigned input_count() const { return family==1?2:family==2?3:12; }
  unsigned depth() const { return family==3?3:1; }
  unsigned degree() const { return (family==3?8:2)*(length-1); }
  unsigned points() const { unsigned k=1; while(k<=degree()) k*=2; return k; }
};
inline const std::array<Cell,6>& cells() {
  static const std::array<Cell,6> all{{
    {"w1-l16-j1",1,16,1},{"w1-l16-j16",1,16,16},
    {"w1-l256-j1",1,256,1},{"w1-l256-j16",1,256,16},
    {"w2-shallow-l256-j16",2,256,16},{"w2-deep-l256-j16",3,256,16}}};
  return all;
}
inline Cell cell(const std::string& name) {
  for(const auto& c:cells()) if(c.name==name) return c;
  throw std::runtime_error("Unknown core cell");
}
inline std::vector<Words> inputs(const Cell& c) {
  uint64_t state=0x4A45544845434F52ULL^(uint64_t(c.family)<<48)^(uint64_t(c.length)<<16)^c.jobs;
  std::vector<Words> out(c.input_count(),Words(c.length*c.jobs));
  for(auto& owner:out) for(auto& x:owner) x=draw(state);
  return out;
}
inline Words product(const Field& f,const Words& a,const Words& b,unsigned length) {
  Words out(length);
  for(unsigned i=0;i<a.size()&&i<length;++i)
    for(unsigned j=0;j<b.size()&&i+j<length;++j) out[i+j]^=f.mul(a[i],b[j]);
  return out;
}
inline Words oracle(const Field& f,const Cell& c,const std::vector<Words>& in) {
  require(in.size()==c.input_count(),"Oracle input count"); Words out;
  for(unsigned job=0;job<c.jobs;++job) {
    std::vector<Words> level;
    for(unsigned i=0;i<(c.family==3?4u:1u);++i) {
      unsigned first=c.family==1?0:3*i;
      Words a(in[first].begin()+job*c.length,in[first].begin()+(job+1)*c.length);
      Words b(in[first+1].begin()+job*c.length,in[first+1].begin()+(job+1)*c.length);
      Words p=product(f,a,b,c.length);
      if(c.family!=1) for(unsigned j=0;j<c.length;++j) p[j]^=in[first+2][job*c.length+j];
      level.push_back(std::move(p));
    }
    while(level.size()>1) {
      std::vector<Words> next;
      for(unsigned i=0;i<level.size();i+=2) next.push_back(product(f,level[i],level[i+1],c.length));
      level=std::move(next);
    }
    out.insert(out.end(),level[0].begin(),level[0].end());
  }
  return out;
}

class AdditiveCRT {
  using Sparse = std::map<unsigned,uint16_t>;
  const Field& field;
  unsigned log_size;
  std::vector<Sparse> polynomials;
  Words split,inverse_split;
  std::vector<Words> offsets;
  uint16_t evaluate(const Sparse& p,uint16_t x) const {
    uint16_t out=0;
    for(const auto& [degree,a]:p) out^=field.mul(a,field.power(x,degree));
    return out;
  }
  void forward_node(Words f,unsigned level,unsigned alpha,Words& result) const {
    if(!level) { result[alpha]=f.empty()?0:f[0]; return; }
    const unsigned d=1u<<(level-1); f.resize(2*d); Words q(d);
    for(unsigned i=2*d;i-->d;) {
      uint16_t a=f[i]; q[i-d]=a;
      if(a) for(const auto& [degree,b]:polynomials[level-1]) f[i-d+degree]^=field.mul(a,b);
      require(!f[i],"CRT sparse division failed");
    }
    const uint16_t c0=offsets[level][alpha>>level],c1=c0^split[level-1];
    Words left(d),right(d);
    for(unsigned i=0;i<d;++i) { left[i]=f[i]^field.mul(c0,q[i]); right[i]=f[i]^field.mul(c1,q[i]); }
    forward_node(std::move(left),level-1,alpha,result);
    forward_node(std::move(right),level-1,alpha+d,result);
  }
  Words inverse_node(const Words& values,unsigned level,unsigned alpha) const {
    if(!level) return {values[alpha]};
    const unsigned d=1u<<(level-1);
    Words left=inverse_node(values,level-1,alpha),right=inverse_node(values,level-1,alpha+d);
    Words out=left; out.resize(2*d);
    const uint16_t c0=offsets[level][alpha>>level];
    for(unsigned i=0;i<d;++i) {
      const uint16_t a=field.mul(left[i]^right[i],inverse_split[level-1]);
      out[i]^=field.mul(c0,a);
      if(a) for(const auto& [degree,b]:polynomials[level-1]) out[i+degree]^=field.mul(a,b);
    }
    return out;
  }
public:
  const unsigned size;
  AdditiveCRT(const Field& f,unsigned k):field(f),log_size(0),size(k) {
    require(k>=2&&k<=65536&&!(k&(k-1)),"Unsupported additive CRT size");
    while((1u<<log_size)<k) ++log_size;
    polynomials.push_back({{1,1}});
    for(unsigned i=0;i<log_size;++i) {
      const auto& previous=polynomials.back(); const uint16_t c=evaluate(previous,uint16_t(1u<<i));
      require(c!=0,"Dependent additive basis"); Sparse current;
      for(const auto& [degree,a]:previous) current[2*degree]=field.mul(a,a);
      for(const auto& [degree,a]:previous) current[degree]^=field.mul(c,a);
      for(auto it=current.begin();it!=current.end();) { if(!it->second) it=current.erase(it); else ++it; }
      polynomials.push_back(std::move(current)); split.push_back(c); inverse_split.push_back(field.power(c,65534));
    }
    offsets.resize(log_size+1);
    for(unsigned level=1;level<=log_size;++level)
      for(unsigned alpha=0;alpha<size;alpha+=1u<<level)
        offsets[level].push_back(evaluate(polynomials[level-1],uint16_t(alpha)));
  }
  Words forward(const Words& coefficients) const {
    require(!coefficients.empty()&&coefficients.size()<=size,"CRT forward size");
    Words out(size); forward_node(coefficients,log_size,0,out); return out;
  }
  Words inverse(const Words& values) const {
    require(values.size()==size,"CRT inverse size"); return inverse_node(values,log_size,0);
  }
  uint16_t vanishing(uint16_t x) const { return evaluate(polynomials.back(),x); }
};
inline uint16_t horner(const Field& f,const Words& coefficients,uint16_t x) {
  uint16_t out=0;
  for(auto it=coefficients.rbegin();it!=coefficients.rend();++it) out=f.mul(out,x)^*it;
  return out;
}
inline std::vector<Words> prepare(const Cell& c,const AdditiveCRT& codec,const std::vector<Words>& in) {
  std::vector<Words> out; out.reserve(in.size());
  for(const auto& owner:in) {
    Words values; values.reserve(c.jobs*codec.size);
    for(unsigned j=0;j<c.jobs;++j) {
      Words p(owner.begin()+j*c.length,owner.begin()+(j+1)*c.length);
      const auto v=codec.forward(p); values.insert(values.end(),v.begin(),v.end());
    }
    out.push_back(std::move(values));
  }
  return out;
}
} // namespace core
