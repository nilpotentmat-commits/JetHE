// Typed arithmetic for the NEW unscaled, acyclic composition implementation.
// No keys, randomness, encryption policy, I/O, threads, or performance claims.
// Canonical residues; exact 256-bit CRT (not floating-point reconstruction).
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using U = uint64_t;
using I = int64_t;
using V = std::vector<U>;
using Wide = unsigned __int128;
static thread_local std::string error_text;
static void need(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
static U add(U a, U b, U p) { U x=a+b; return x>=p ? x-p : x; }
static U sub(U a, U b, U p) { return a>=b ? a-b : p-(b-a); }
static U mul(U a, U b, U p) {
    const U base=U(1)<<60, mask=base-1, c=base-p;
    if(c < (U(1)<<31)) {
        const Wide x=Wide(a)*b;
        const Wide y=(U(x)&mask)+(x>>60)*c;
        const U z=(U(y)&mask)+U(y>>60)*c;
        const U v=(z&mask)+(z>>60)*c;
        return v>=p?v-p:v;
    }
    return U(Wide(a)*b%p);
}
static U shoup(U a,U w,U quotient,U p) {
    const U q=U((Wide(a)*quotient)>>64);
    const U r=a*w-q*p;
    return r>=p?r-p:r;
}
static U power(U a, U n, U p) {
    U out=1;
    while(n) { if(n&1) out=mul(out,a,p); a=mul(a,a,p); n>>=1; }
    return out;
}
static U signed_residue(I x, U p) { return x<0 ? p-U(-(x+1))-1 : U(x); }
static constexpr std::array<U,4> primes = {
    1152921504002872321ULL,1152921503566671361ULL,
    1152921503264686081ULL,1152921503096916481ULL};
static constexpr std::array<U,4> generators = {38,14,7,13};

struct Big {
    std::array<U,4> v{};
    explicit Big(U x=0) {v[0]=x;}
    int compare(const Big& b) const {
        for(int j=3;j>=0;--j) if(v[j]!=b.v[j]) return v[j]>b.v[j]?1:-1;
        return 0;
    }
    void times_add(U factor, U extra) {
        Wide carry=extra;
        for(auto& x:v) {carry+=Wide(x)*factor; x=U(carry); carry>>=64;}
        need(carry==0,"256-bit overflow");
    }
    void minus(const Big& b) {
        need(compare(b)>=0,"negative unsigned difference");
        U borrow=0;
        for(unsigned j=0;j<4;++j) {
            Wide rhs=Wide(b.v[j])+borrow; U next=Wide(v[j])<rhs;
            v[j]-=U(rhs); borrow=next;
        }
        need(!borrow,"subtraction overflow");
    }
    void shift(unsigned n) {
        need(n>0&&n<64,"bad small shift");
        for(unsigned j=0;j<3;++j) v[j]=(v[j]>>n)|(v[j+1]<<(64-n));
        v[3]>>=n;
    }
    void twos_complement() {
        U carry=1;
        for(auto& x:v) {x=~x; U old=x; x+=carry; carry=carry&&x<old;}
    }
    unsigned bits() const {
        for(int j=3;j>=0;--j) if(v[j]) return 64*j+64-__builtin_clzll(v[j]);
        return 0;
    }
};

struct NTT {
    unsigned n;
    U p;
    std::vector<unsigned> reverse;
    std::vector<V> twiddles, shoup_quotients;
    NTT(unsigned size,U root,U prime):n(size),p(prime),reverse(size) {
        need(n&&!(n&(n-1))&&power(root,n,p)==1,"bad NTT order");
        need(n==1||power(root,n/2,p)!=1,"nonprimitive NTT root");
        unsigned bits=0; while((1u<<bits)<n) ++bits;
        for(unsigned j=0;j<n;++j) {unsigned x=j,r=0; for(unsigned k=0;k<bits;++k){r=(r<<1)|(x&1);x>>=1;} reverse[j]=r;}
        for(unsigned span=2;span<=n;span*=2) {
            V t(span/2); U w=power(root,n/span,p); t[0]=1;
            for(unsigned j=1;j<t.size();++j)t[j]=mul(t[j-1],w,p);
            V quot(t.size());
            for(unsigned j=0;j<t.size();++j)quot[j]=U((Wide(t[j])<<64)/p);
            shoup_quotients.push_back(std::move(quot));
            twiddles.push_back(std::move(t));
        }
    }
    V run(const V& input) const {
        need(input.size()==n,"NTT shape"); V out(n);
        for(unsigned j=0;j<n;++j)out[j]=input[reverse[j]];
        const U twice=2*p;
        unsigned span=2,stage=0;
        for(const auto& tw:twiddles) {
            const auto& quot=shoup_quotients[stage++];
            for(unsigned start=0;start<n;start+=span)for(unsigned j=0;j<span/2;++j) {
                U a=out[start+j],b=out[start+j+span/2];
                if(a>=twice)a-=twice;
                if(j) {
                    const U q=U((Wide(b)*quot[j])>>64);
                    b=b*tw[j]-q*p; // Exact nonnegative representative below 2p.
                } else if(b>=twice)b-=twice;
                out[start+j]=a+b;
                out[start+j+span/2]=a+twice-b;
            }
            span*=2;
        }
        for(U& x:out) {if(x>=twice)x-=twice;if(x>=p)x-=p;}
        return out;
    }

};

struct Dyadic {
    unsigned n; U p,root;
    NTT forward,backward;
    V twists,untwists;
    Dyadic(unsigned length,U prime,U gen):n(length),p(prime),
        root(power(gen,(p-1)/(2*n),p)),
        forward(n,mul(root,root,p),p),backward(n,power(root,p-3,p),p),
        twists(n),untwists(n) {
        need((p-1)%(2*n)==0,"missing tensor root");
        U inverse=power(root,p-2,p), invn=power(n,p-2,p);
        twists[0]=1;untwists[0]=invn;
        for(unsigned j=1;j<n;++j){twists[j]=mul(twists[j-1],root,p);untwists[j]=mul(untwists[j-1],inverse,p);}
    }
    V run(const V& x,bool inverse) const {
        need(x.size()==n,"dyadic shape");
        if(inverse){V y=backward.run(x); for(unsigned j=0;j<n;++j)y[j]=mul(y[j],untwists[j],p);return y;}
        V y=x;for(unsigned j=1;j<n;++j)y[j]=mul(y[j],twists[j],p);return forward.run(y);
    }
};

struct Normal {
    unsigned r,n; U p,root;
    std::vector<unsigned> indices;
    NTT forward,backward;
    std::array<V,2> kernels;
    Normal(unsigned conductor,U prime,U gen):r(conductor),n(r-1),p(prime),
        root(power(gen,(p-1)/r,p)),indices(n),
        forward(n,power(gen,(p-1)/n,p),p),
        backward(n,power(power(gen,(p-1)/n,p),p-2,p),p) {
        need((r==17||r==257)&&(p-1)%r==0,"normal axis unsupported");
        unsigned index_gen=2;while(power(index_gen,n/2,r)==1)++index_gen;
        indices[0]=1;for(unsigned j=1;j<n;++j)indices[j]=indices[j-1]*index_gen%r;
        V h(n),k(n);U invr=power(r,p-2,p), invn=power(n,p-2,p), invroot=power(root,p-2,p);
        for(unsigned j=0;j<n;++j) {
            h[j]=power(root,indices[(n-j)%n],p);
            k[j]=mul(sub(power(invroot,indices[j],p),1,p),invr,p);
        }
        kernels[0]=forward.run(h); kernels[1]=forward.run(k);
        for(auto& kernel:kernels)for(auto& x:kernel)x=mul(x,invn,p);
    }
    V run(const V& x,bool inverse) const {
        need(x.size()==n,"normal shape"); V input(n),result(n);
        for(unsigned j=0;j<n;++j)input[j]=x[indices[inverse?(n-j)%n:j]-1];
        V spectrum=forward.run(input);
        for(unsigned j=0;j<n;++j)spectrum[j]=mul(spectrum[j],kernels[inverse][j],p);
        V output=backward.run(spectrum);
        for(unsigned j=0;j<n;++j)result[indices[inverse?j:(n-j)%n]-1]=output[j];
        return result;
    }
};

struct Context {
    unsigned length,limbs,dimension;
    bool conventional;
    std::array<std::unique_ptr<Normal>,4> normal,first;
    std::map<std::pair<unsigned,unsigned>,std::unique_ptr<Dyadic>> dyadic;
    std::array<Big,5> moduli;
    U inv[4][4]{};
    Context(unsigned len,unsigned channels,bool conv):length(len),limbs(channels),dimension(len*256),conventional(conv) {
        need(channels>=1&&channels<=4,"limb count");
        need(len&&!(len&(len-1))&&len<=256&&(!conv||len==16),"length/profile");
        moduli[0]=Big(1);
        for(unsigned a=0;a<channels;++a) {
            moduli[a+1]=moduli[a];moduli[a+1].times_add(primes[a],0);
            normal[a]=std::make_unique<Normal>(257,primes[a],generators[a]);
            if(conv)first[a]=std::make_unique<Normal>(17,primes[a],generators[a]);
            for(unsigned j=0;j<a;++j)inv[j][a]=power(primes[j]%primes[a],primes[a]-2,primes[a]);
        }
    }
    Dyadic& axis(unsigned channel,unsigned len) {
        auto key=std::make_pair(channel,len);
        auto pos=dyadic.find(key);
        if(pos==dyadic.end())pos=dyadic.emplace(key,std::make_unique<Dyadic>(len,primes[channel],generators[channel])).first;
        return *pos->second;
    }
    void channels(unsigned a) const {need(a>=1&&a<=limbs,"context channel count");}
    V transform(const U* source,unsigned channel,bool inverse,unsigned len=0) {
        if(!len)len=length;
        need(channel<limbs&&len&&!(len&(len-1))&&len<=length,"transform dimensions");
        need(!conventional||len==length,"conventional relative transform");
        V out(source,source+len*256),scratch;
        auto extension=[&](){
            if(len<16) {
                for(unsigned i=0;i<len;++i) {
                    scratch.assign(out.begin()+i*256,out.begin()+(i+1)*256);
                    V y=normal[channel]->run(scratch,inverse);
                    std::copy(y.begin(),y.end(),out.begin()+i*256);
                }
                return;
            }
            const Normal& d=*normal[channel];
            const unsigned n=d.n;
            const U p=d.p,twice=2*p;
            V tensor(n*len);
            for(unsigned j=0;j<n;++j) {
                const unsigned k=d.forward.reverse[j];
                const unsigned source=d.indices[inverse?(n-k)%n:k]-1;
                for(unsigned i=0;i<len;++i)tensor[j*len+i]=out[i*n+source];
            }
            auto butterflies=[&](const NTT& t){
                unsigned span=2,stage=0;
                for(const auto& tw:t.twiddles) {
                    const auto& quot=t.shoup_quotients[stage++];
                    for(unsigned start=0;start<n;start+=span)for(unsigned j=0;j<span/2;++j) {
                        const unsigned one=(start+j)*len,two=(start+j+span/2)*len;
                        const U w=tw[j],pre=quot[j];
                        for(unsigned i=0;i<len;++i) {
                            U a=tensor[one+i],b=tensor[two+i];
                            if(a>=twice)a-=twice;
                            if(j) {const U q=U((Wide(b)*pre)>>64);b=b*w-q*p;}
                            else if(b>=twice)b-=twice;
                            tensor[one+i]=a+b;
                            tensor[two+i]=a+twice-b;
                        }
                    }
                    span*=2;
                }
            };
            butterflies(d.forward);
            for(unsigned j=0;j<n;++j)for(unsigned i=0;i<len;++i) {
                U x=tensor[j*len+i];if(x>=twice)x-=twice;if(x>=p)x-=p;
                tensor[j*len+i]=mul(x,d.kernels[inverse][j],p);
            }
            for(unsigned j=0;j<n;++j) {
                const unsigned k=d.backward.reverse[j];
                if(j<k)for(unsigned i=0;i<len;++i)
                    std::swap(tensor[j*len+i],tensor[k*len+i]);
            }
            butterflies(d.backward);
            for(unsigned j=0;j<n;++j) {
                const unsigned target=d.indices[inverse?j:(n-j)%n]-1;
                for(unsigned i=0;i<len;++i) {
                    U x=tensor[j*len+i];if(x>=twice)x-=twice;if(x>=p)x-=p;
                    out[i*n+target]=x;
                }
            }
        };
        auto first_axis=[&](){
            if(conventional) {
                scratch.resize(len);
                for(unsigned e=0;e<256;++e) {
                    for(unsigned i=0;i<len;++i)scratch[i]=out[i*256+e];
                    V y=first[channel]->run(scratch,inverse);
                    for(unsigned i=0;i<len;++i)out[i*256+e]=y[i];
                }
                return;
            }
            const Dyadic& d=axis(channel,len);
            const NTT& t=inverse?d.backward:d.forward;
            const U p=d.p,twice=2*p;
            V tensor(len*256);
            for(unsigned j=0;j<len;++j) {
                const unsigned i=t.reverse[j];
                const U twist=inverse?1:d.twists[i];
                for(unsigned e=0;e<256;++e)
                    tensor[j*256+e]=twist==1?out[i*256+e]:mul(out[i*256+e],twist,p);
            }
            unsigned span=2,stage=0;
            for(const auto& tw:t.twiddles) {
                const auto& quot=t.shoup_quotients[stage++];
                for(unsigned start=0;start<len;start+=span)for(unsigned j=0;j<span/2;++j) {
                    const unsigned one=(start+j)*256,two=(start+j+span/2)*256;
                    const U w=tw[j],pre=quot[j];
                    for(unsigned e=0;e<256;++e) {
                        U a=tensor[one+e],b=tensor[two+e];
                        if(a>=twice)a-=twice;
                        if(j) {const U q=U((Wide(b)*pre)>>64);b=b*w-q*p;}
                        else if(b>=twice)b-=twice;
                        tensor[one+e]=a+b;
                        tensor[two+e]=a+twice-b;
                    }
                }
                span*=2;
            }
            for(unsigned i=0;i<len;++i)for(unsigned e=0;e<256;++e) {
                U x=tensor[i*256+e];if(x>=twice)x-=twice;if(x>=p)x-=p;
                out[i*256+e]=inverse?mul(x,d.untwists[i],p):x;
            }
        };
        if(inverse){extension();first_axis();}else{first_axis();extension();}
        return out;
    }
    Big crt(const std::array<U,4>& residues,unsigned a) const {
        std::array<U,4> digits{};
        for(unsigned i=0;i<a;++i) {
            U d=residues[i]; need(d<primes[i],"noncanonical CRT residue");
            for(unsigned j=0;j<i;++j)d=mul(sub(d,digits[j]%primes[i],primes[i]),inv[j][i],primes[i]);
            digits[i]=d;
        }
        Big result(digits[a-1]);for(int i=int(a)-2;i>=0;--i)result.times_add(primes[i],digits[i]);
        return result;
    }
    std::vector<V> recover(const U* source,unsigned a) {
        channels(a);std::vector<V> values;
        for(unsigned j=0;j<a;++j)values.push_back(transform(source+j*dimension,j,true));
        return values;
    }
    V hasse(const U* source,unsigned channel,unsigned r) {
        need(!conventional&&r&&!(r&(r-1))&&2*r<=length,"Hasse order");
        unsigned h=2*r,blocks=length/h;U p=primes[channel],root=axis(channel,length).root;
        NTT backward(h,power(power(root,2*blocks,p),p-2,p),p),forward(r,power(root,4*blocks,p),p);
        U oddroot=power(root,2*blocks,p);V twists(r,1),result(dimension),values(h);
        for(unsigned i=1;i<r;++i)twists[i]=mul(twists[i-1],oddroot,p);
        for(unsigned j=0;j<blocks;++j) {
            U scale=power(mul(h,power(root,(2*j+1)*r,p),p),p-2,p);
            for(unsigned e=0;e<256;++e) {
                for(unsigned k=0;k<h;++k)values[k]=source[(j+blocks*k)*256+e];
                V all=backward.run(values),coeff(r);
                for(unsigned k=0;k<r;++k)coeff[k]=mul(all[k+r],scale,p);
                V even=forward.run(coeff);
                for(unsigned k=1;k<r;++k)coeff[k]=mul(coeff[k],twists[k],p);
                V odd=forward.run(coeff);
                for(unsigned k=0;k<r;++k){result[(j+blocks*2*k)*256+e]=even[k];result[(j+blocks*(2*k+1))*256+e]=odd[k];}
            }
        }
        return result;
    }
};

#define API extern "C" __declspec(dllexport)
#define BEGIN try { error_text.clear();
#define END return 0; } catch(const std::exception& e) {error_text=e.what(); return -1;}
API const char* jc_error() {return error_text.c_str();}
API void* jc_create(unsigned length,unsigned limbs,unsigned conventional) {
    try{return new Context(length,limbs,conventional!=0);}catch(const std::exception& e){error_text=e.what();return nullptr;}
}
API void jc_destroy(void* handle) {delete static_cast<Context*>(handle);}
API int jc_transform(void* handle,const U* in,U* out,unsigned channel,unsigned inverse,unsigned length) {
    BEGIN auto& c=*static_cast<Context*>(handle);V result=c.transform(in,channel,inverse!=0,length);
    std::copy(result.begin(),result.end(),out); END
}
API int jc_point(void* handle,const U* a,const U* b,U* out,unsigned limbs,unsigned op) {
    BEGIN auto& c=*static_cast<Context*>(handle);c.channels(limbs);need(op<=2,"point operation");
    for(unsigned j=0;j<limbs;++j)for(unsigned i=0;i<c.dimension;++i) {
        auto k=j*c.dimension+i;out[k]=op==0?add(a[k],b[k],primes[j]):op==1?mul(a[k],b[k],primes[j]):sub(a[k],b[k],primes[j]);
    } END
}
API int jc_validate(void* handle,const U* data,unsigned limbs) {
    BEGIN auto& c=*static_cast<Context*>(handle);c.channels(limbs);
    for(unsigned j=0;j<limbs;++j) {
        for(unsigned i=0;i<c.dimension;++i) {need(data[j*c.dimension+i]<primes[j],"noncanonical spectrum");}
    }
    END
}
API int jc_lift(void* handle,const I* in,U* out,unsigned limbs) {
    BEGIN auto& c=*static_cast<Context*>(handle);c.channels(limbs);V residues(c.dimension);
    for(unsigned j=0;j<limbs;++j) {
        for(unsigned i=0;i<c.dimension;++i){need(in[i]>-I(primes[j])&&in[i]<I(primes[j]),"signed lift range");residues[i]=signed_residue(in[i],primes[j]);}
        V result=c.transform(residues.data(),j,false);std::copy(result.begin(),result.end(),out+j*c.dimension);
    } END
}
API int jc_digits(void* handle,const U* in,I* out,unsigned limbs,unsigned width) {
    BEGIN auto& c=*static_cast<Context*>(handle);c.channels(limbs);need(width==40||width==44||width==45||width==48||width==60,"supported gadget widths40/44/45/48/60");
    unsigned g=(c.moduli[limbs].bits()+width-1)/width;need(g*width<=256,"digit capacity");
    auto recovered=c.recover(in,limbs);Big half=c.moduli[limbs];half.shift(1);U base=U(1)<<width,bound=base/2;
    for(unsigned i=0;i<c.dimension;++i) {
        std::array<U,4> rs{};for(unsigned j=0;j<limbs;++j)rs[j]=recovered[j][i];Big x=c.crt(rs,limbs);
        bool negative=x.compare(half)>0;
        if(negative){Big mag=c.moduli[limbs];mag.minus(x);mag.twos_complement();x=mag;}
        U carry=0;
        for(unsigned j=0;j<g;++j) {
            U chunk=(x.v[0]&(base-1))+carry;I d;
            if(j+1==g)d=I(chunk)-(negative?I(base):0);
            else {carry=chunk>=bound;d=I(chunk)-I(base*carry);}
            need(d>=-I(bound)&&d<=I(bound),"digit outside envelope");out[j*c.dimension+i]=d;x.shift(width);
        }
    } END
}
API int jc_hasse(void* handle,const U* in,U* out,unsigned limbs,unsigned r) {
    BEGIN auto& c=*static_cast<Context*>(handle);c.channels(limbs);
    for(unsigned j=0;j<limbs;++j){V result=c.hasse(in+j*c.dimension,j,r);std::copy(result.begin(),result.end(),out+j*c.dimension);} END
}
API int jc_relative(void* handle,const I* in,U* out,unsigned limbs,unsigned index,unsigned r) {
    BEGIN auto& c=*static_cast<Context*>(handle);c.channels(limbs);
    need(!c.conventional&&r&&!(r&(r-1))&&2*r<=c.length&&index<2*r,"relative digit shape");
    unsigned h=2*r,len=c.length/h;V short_coeff(len*256);
    for(unsigned j=0;j<limbs;++j) {
        for(unsigned i=0;i<len;++i)for(unsigned e=0;e<256;++e) {
            I x=in[(index+h*i)*256+e];need(x>-I(primes[j])&&x<I(primes[j]),"relative lift range");short_coeff[i*256+e]=signed_residue(x,primes[j]);
        }
        V spectrum=c.transform(short_coeff.data(),j,false,len);
        for(unsigned i=0;i<c.length;++i)for(unsigned e=0;e<256;++e)out[j*c.dimension+i*256+e]=spectrum[(i%len)*256+e];
    } END
}
API int jc_drop(void* handle,const U* in,U* out,unsigned limbs) {
    BEGIN auto& c=*static_cast<Context*>(handle);c.channels(limbs);need(limbs>=2,"drop final channel");
    U dropped=primes[limbs-1];V last=c.transform(in+(limbs-1)*c.dimension,limbs-1,true),residues(c.dimension);
    std::vector<I> remainder(c.dimension);
    for(unsigned i=0;i<c.dimension;++i)remainder[i]=(last[i]&1)?I(last[i])-I(dropped):I(last[i]);
    for(unsigned j=0;j<limbs-1;++j) {
        for(unsigned i=0;i<c.dimension;++i)residues[i]=signed_residue(remainder[i],primes[j]);
        V lifted=c.transform(residues.data(),j,false);U inv=power(dropped%primes[j],primes[j]-2,primes[j]);
        for(unsigned i=0;i<c.dimension;++i)out[j*c.dimension+i]=mul(sub(in[j*c.dimension+i],lifted[i],primes[j]),inv,primes[j]);
    } END
}
API int jc_phase_check(void* handle,const U* phase,const uint8_t* mu,const U* bound,U* maximum,unsigned limbs) {
    BEGIN auto& c=*static_cast<Context*>(handle);c.channels(limbs);auto values=c.recover(phase,limbs);
    Big half=c.moduli[limbs],limit,max;half.shift(1);std::copy(bound,bound+4,limit.v.begin());
    for(unsigned i=0;i<c.dimension;++i) {
        need(mu[i]<=1,"nonbinary plaintext lift");std::array<U,4> rs{};
        for(unsigned j=0;j<limbs;++j){rs[j]=values[j][i];}
        Big x=c.crt(rs,limbs);
        bool negative=x.compare(half)>0;
        if(negative){Big mag=c.moduli[limbs];mag.minus(x);x=mag;}
        need((x.v[0]&1)==mu[i],"plaintext parity mismatch");
        if(negative)x.times_add(1,mu[i]);else if(mu[i])x.minus(Big(1));
        x.shift(1);need(x.compare(limit)<=0,"phase outside bound");if(x.compare(max)>0)max=x;
    }
    std::copy(max.v.begin(),max.v.end(),maximum); END
}

struct Field {
    std::array<unsigned,65536> logs{};
    std::vector<uint16_t> exp;
    static uint16_t slow(unsigned a,unsigned b) {
        unsigned out=0;while(b){if(b&1)out^=a;b>>=1;a<<=1;if(a&65536)a^=0x1100b;}return uint16_t(out);
    }
    static uint16_t pow_slow(uint16_t a,unsigned n) {
        uint16_t out=1;while(n){if(n&1)out=slow(out,a);a=slow(a,a);n>>=1;}return out;
    }
    Field():exp(2*65535) {
        unsigned gen=2;
        while(gen<50){bool ok=true;for(unsigned p:{3u,5u,17u,257u})ok&=pow_slow(gen,65535/p)!=1;if(ok)break;++gen;}
        need(gen<50,"field generator");unsigned x=1;
        for(unsigned j=0;j<65535;++j){logs[x]=j;exp[j]=exp[j+65535]=uint16_t(x);x=slow(x,gen);}
        need(x==1,"field order");
    }
    uint16_t product(uint16_t a,uint16_t b) const {return a&&b?exp[logs[a]+logs[b]]:0;}
};
static Field& field(){static Field f;return f;}
static void series_product(const uint16_t* a,const uint16_t* b,uint16_t* out,unsigned length) {
    std::fill(out,out+length,0);auto& f=field();
    for(unsigned i=0;i<length;++i)for(unsigned j=0;j<length-i;++j)out[i+j]^=f.product(a[i],b[j]);
}
API int jc_series_product(const uint16_t* a,const uint16_t* b,uint16_t* out,unsigned length,unsigned jobs) {
    BEGIN need(length&&length<=256&&jobs&&jobs<=16,"field shape");
    for(unsigned lane=0;lane<jobs;++lane){series_product(a+lane*length,b+lane*length,out+lane*length,length);} END
}
API int jc_series_horner(const uint16_t* a,const uint16_t* b,uint16_t* out,unsigned length,unsigned jobs) {
    BEGIN need(length&&length<=256&&jobs&&jobs<=16,"Horner shape");
    std::vector<uint16_t> current(length),next(length);
    for(unsigned lane=0;lane<jobs;++lane) {
        need(b[lane*length]==0,"composition promise g0=0");std::fill(current.begin(),current.end(),0);
        for(int j=int(length)-1;j>=0;--j){series_product(current.data(),b+lane*length,next.data(),length);next[0]^=a[lane*length+j];current.swap(next);}
        std::copy(current.begin(),current.end(),out+lane*length);
    } END
}
API int jc_scale(void* handle,const U* in,U* out,unsigned limbs,unsigned exponent) {
    BEGIN auto& c=*static_cast<Context*>(handle);c.channels(limbs);
    for(unsigned j=0;j<limbs;++j){U scalar=power(2,exponent,primes[j]);for(unsigned i=0;i<c.dimension;++i)out[j*c.dimension+i]=mul(in[j*c.dimension+i],scalar,primes[j]);} END
}
// Map independent uniform 64-bit words to exact finite laws. The caller
// supplies more words after rejection; no abort/resampling of whole vectors.
API int jc_sample(const U* words,U count,I* out,U wanted,unsigned kind,U prime,U* written) {
    BEGIN need(kind<=2&&prime< (U(1)<<61),"sampler mode");
    U done=0,modulus=kind==0?3:prime;
    need(kind==1||modulus>1,"sampler modulus");
    Wide limit=kind==1?0:((Wide(1)<<64)/modulus)*modulus;
    for(U j=0;j<count&&done<wanted;++j) {
        U x=words[j];
        if(kind==1)out[done++]=I(__builtin_popcountll(x&((U(1)<<20)-1)))-I(__builtin_popcountll((x>>20)&((U(1)<<20)-1)));
        else if(Wide(x)<limit)out[done++]=I(x%modulus)-(kind==0?1:0);
    }
    *written=done; END
}
