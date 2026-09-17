// Separate extension: the accepted arithmetic source and Windows DLL stay frozen.
#ifndef _WIN32
#define __declspec(x) __attribute__((visibility("default")))
#endif
#include "composition_native_core.cpp"

struct HoistPlan {
    unsigned h,len;
    NTT cyclic;
    V twists;
    HoistPlan(Context& c,unsigned channel,unsigned r):h(2*r),len(c.length/h),
      cyclic(h,power(c.axis(channel,c.length).root,2*len,primes[channel]),primes[channel]),
      twists(c.length,1) {
        const U p=primes[channel],root=c.axis(channel,c.length).root;
        for(unsigned u=0;u<len;++u){
            const U x=power(root,2*u+1,p);
            for(unsigned i=1;i<h;++i)twists[u*h+i]=mul(twists[u*h+i-1],x,p);
        }
    }
};
struct OptimizedContext:Context {
    std::map<std::pair<unsigned,unsigned>,std::unique_ptr<HoistPlan>> plans;
    OptimizedContext(unsigned length,unsigned limbs):Context(length,limbs,false){
        // All roots/mixing constants are public setup work, before evaluation.
        for(unsigned a=0;a<limbs;++a){
            for(unsigned len=1;len<=length;len*=2)axis(a,len);
            for(unsigned r:{1u,2u,4u,8u})if(2*r<=length)
                plans.emplace(std::make_pair(a,r),std::make_unique<HoistPlan>(*this,a,r));
        }
    }
};
API void* jc_opt_create(unsigned length,unsigned limbs){
    try{return static_cast<Context*>(new OptimizedContext(length,limbs));}
    catch(const std::exception& e){error_text=e.what();return nullptr;}
}
API void jc_opt_destroy(void* handle){delete static_cast<OptimizedContext*>(static_cast<Context*>(handle));}
API int jc_hoist(void* handle,const I* in,U* compact,U* full,unsigned limbs,unsigned r){
    BEGIN auto& c=*static_cast<OptimizedContext*>(static_cast<Context*>(handle));c.channels(limbs);
    need(r&&(r==1||r==2||r==4||r==8)&&2*r<=c.length,"hoist rank");
    const unsigned h=2*r,len=c.length/h;
    V small(len*256),weighted(h);
    for(unsigned a=0;a<limbs;++a){
        const auto& plan=*c.plans.at({a,r});const U p=primes[a];
        for(unsigned i=0;i<h;++i){
            for(unsigned u=0;u<len;++u)for(unsigned e=0;e<256;++e){
                const I x=in[(i+h*u)*256+e];need(x>-I(p)&&x<I(p),"hoist digit range");
                small[u*256+e]=signed_residue(x,p);
            }
            V spectrum=c.transform(small.data(),a,false,len);
            std::copy(spectrum.begin(),spectrum.end(),compact+a*c.dimension+i*len*256);
        }
        for(unsigned u=0;u<len;++u)for(unsigned e=0;e<256;++e){
            weighted[0]=compact[a*c.dimension+u*256+e];
            for(unsigned i=1;i<h;++i)
                weighted[i]=mul(compact[a*c.dimension+i*len*256+u*256+e],plan.twists[u*h+i],p);
            const V y=plan.cyclic.run(weighted); // NO negacyclic twist or inverse scaling.
            for(unsigned v=0;v<h;++v)full[a*c.dimension+(u+len*v)*256+e]=y[v];
        }
    } END
}
API int jc_relative_point(void* handle,const U* compact,const U* row,U* out,unsigned limbs,unsigned r,unsigned index){
    BEGIN auto& c=*static_cast<Context*>(handle);c.channels(limbs);
    need(r&&(r==1||r==2||r==4||r==8)&&2*r<=c.length&&index<2*r,"compact relative index");
    const unsigned len=c.length/(2*r);
    for(unsigned a=0;a<limbs;++a)for(unsigned q=0;q<c.length;++q)for(unsigned e=0;e<256;++e){
        const unsigned k=a*c.dimension+q*256+e;
        out[k]=mul(compact[a*c.dimension+index*len*256+(q%len)*256+e],row[k],primes[a]);
    } END
}
