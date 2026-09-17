#pragma once
// Exact companion to research/composition_fixture.py, public fixture only.
#include <array>
#include <cstdint>
#include <stdexcept>

namespace fixture {
constexpr unsigned L=256,JOBS=16;
using Jet=std::array<uint16_t,L>;
struct Inputs { std::array<Jet,JOBS> f{},g{}; };
inline Inputs inputs(){
    uint64_t state=UINT64_C(0x4a657448454c3235);
    auto draw=[&](){
        state+=UINT64_C(0x9e3779b97f4a7c15);
        uint64_t z=state;z=(z^(z>>30))*UINT64_C(0xbf58476d1ce4e5b9);
        z=(z^(z>>27))*UINT64_C(0x94d049bb133111eb);
        return uint16_t(z^(z>>31));
    };
    Inputs out;
    for(unsigned j=0;j<JOBS;++j){
        for(auto& x:out.f[j])x=draw();
        for(auto& x:out.g[j])x=draw();
        out.f[j][0]|=1;
        unsigned v=j==2?2:j==3?4:1;
        for(unsigned i=0;i<v;++i)out.g[j][i]=0;
        if(!out.g[j][v])out.g[j][v]=1;
        if(j==0)out.g[j].fill(0);
        if(j==1){out.g[j].fill(0);out.g[j][1]=1;}
    }
    return out;
}
inline uint64_t checksum(const Inputs& in){
    uint64_t h=UINT64_C(14695981039346656037);
    for(unsigned j=0;j<JOBS;++j)for(const Jet* v:{&in.f[j],&in.g[j]})for(uint16_t x:*v){
        h=(h^(x&255))*UINT64_C(1099511628211);
        h=(h^(x>>8))*UINT64_C(1099511628211);
    }
    return h;
}
inline uint16_t multiply(unsigned a,unsigned b){
    unsigned out=0;
    while(b){if(b&1)out^=a;b>>=1;a<<=1;if(a&65536)a^=0x1100b;}
    return uint16_t(out);
}
inline Jet series_product(const Jet& a,const Jet& b){
    Jet out{};
    for(unsigned i=0;i<L;++i)if(a[i])for(unsigned j=0;j<L-i;++j)if(b[j])out[i+j]^=multiply(a[i],b[j]);
    return out;
}
inline Jet horner(const Jet& f,const Jet& g){
    Jet out{};
    for(unsigned i=L;i>0;--i){out=series_product(out,g);out[0]^=f[i-1];}
    return out;
}
} // namespace fixture
