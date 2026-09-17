// Isolated existing-factorization extension. The included sources stay frozen.
#include "composition_optimized_core.cpp"

struct PaidHasseContext:OptimizedContext {
    std::map<std::pair<unsigned,unsigned>,V> powers;
    PaidHasseContext(unsigned length,unsigned limbs):OptimizedContext(length,limbs) {
        // Public powers only; build all valid changed-map/channel combinations.
        for(unsigned a=0;a<limbs;++a)for(unsigned r:{2u,4u,8u})if(2*r<=length) {
            V values(length*r);const U p=primes[a],root=axis(a,length).root;
            for(unsigned k=0;k<length;++k) {
                const U x=power(root,2*k+1,p);U value=1;
                for(unsigned j=1;j<=r;++j) {
                    value=mul(value,x,p);values[k*r+j-1]=value;
                }
            }
            powers.emplace(std::make_pair(a,r),std::move(values));
        }
    }
};

API void* jc_paid_create(unsigned length,unsigned limbs) {
    try{return static_cast<Context*>(new PaidHasseContext(length,limbs));}
    catch(const std::exception& e){error_text=e.what();return nullptr;}
}
API void jc_paid_destroy(void* handle) {
    delete static_cast<PaidHasseContext*>(static_cast<Context*>(handle));
}
API int jc_paid_multiplier(void* handle,const U* compact,U* out,
                           unsigned limbs,unsigned r,unsigned index) {
    BEGIN auto& c=*static_cast<PaidHasseContext*>(static_cast<Context*>(handle));
    c.channels(limbs);
    need((r==2||r==4||r==8)&&2*r<=c.length&&index<=r,"paid Hasse multiplier shape");
    const unsigned len=c.length/(2*r);
    for(unsigned a=0;a<limbs;++a) {
        const U p=primes[a];const V& tw=c.powers.at({a,r});
        for(unsigned k=0;k<c.length;++k) {
            const unsigned offset=a*c.dimension+(k%len)*256;
            for(unsigned e=0;e<256;++e) {
                U value;
                if(index<r) {
                    const U u=compact[offset+index*len*256+e];
                    const U v=compact[offset+(index+r)*len*256+e];
                    value=sub(u,mul(tw[k*r+r-1],v,p),p);
                } else {
                    value=compact[offset+r*len*256+e];
                    for(unsigned j=1;j<r;++j)
                        value=add(value,mul(tw[k*r+j-1],compact[offset+(j+r)*len*256+e],p),p);
                }
                out[a*c.dimension+k*256+e]=value;
            }
        }
    } END
}
