#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <limits>
using U=uint64_t;using Wide=unsigned __int128;
#include "arithmetic.hpp"
static constexpr U primes[]={1152921504002872321ULL,1152921503566671361ULL,1152921503264686081ULL};
static constexpr U generators[]={38,14,7};
static constexpr size_t N=65536, WORDS=3*N, COORDS=3*4096, LEAF_WORDS=COORDS*8*7*64;
static thread_local std::string error_text;
struct Cache {unsigned arm;std::vector<U> data;Cache(unsigned a):arm(a),data(LEAF_WORDS*(a+1)) {}};
static bool overlap(const U* a,size_t na,const U* b,size_t nb) {
    const uintptr_t x=reinterpret_cast<uintptr_t>(a),y=reinterpret_cast<uintptr_t>(b);
    if(na>std::numeric_limits<uintptr_t>::max()/8||nb>std::numeric_limits<uintptr_t>::max()/8)return true;
    const uintptr_t ax=na*8,by=nb*8;
    if(x>std::numeric_limits<uintptr_t>::max()-ax||y>std::numeric_limits<uintptr_t>::max()-by)return true;
    return x<y+by&&y<x+ax;
}
extern "C" const char* jet_matrix_error(){return error_text.c_str();}
static U fast_quotient(U w,U p) {
    const U base=U(1)<<60,mask=base-1,c=base-p;
    const Wide t=(Wide(w)*c)<<4;
    const U a=U(t>>60);
    const Wide s=(U(t)&mask)+Wide(a)*c;
    const U d=U(s>>60),v=(U(s)&mask)+d*c;
    return (w<<4)+a+d+U(v>=p);
}
extern "C" void* jet_matrix_create(const U* const* rows,unsigned count,size_t row_words,unsigned arm) {
    try {
        if(!rows||count!=72||row_words!=WORDS||arm>1)throw std::runtime_error("cache shape");
        for(unsigned j=0;j<count;++j) {
            if(!rows[j])throw std::runtime_error("null public row");
            for(unsigned a=0;a<3;++a)for(size_t k=0;k<N;++k)
                if(rows[j][a*N+k]>=primes[a])throw std::runtime_error("noncanonical public row");
        }
        auto result=std::make_unique<Cache>(arm);
        U powers[3][256][9];
        for(unsigned a=0;a<3;++a) {
            const U p=primes[a],alpha=power(generators[a],(p-1)/512,p);
            for(unsigned k=0;k<256;++k) {
                const U t=power(alpha,2*k+1,p);powers[a][k][0]=1;
                for(unsigned i=1;i<=8;++i)powers[a][k][i]=mul(powers[a][k][i-1],t,p);
            }
        }
        U A[32][64];
        for(unsigned a=0;a<3;++a)for(unsigned u=0;u<16;++u)for(unsigned z=0;z<256;++z) {
            const U p=primes[a];const size_t coord=a*4096+u*256+z;
            for(unsigned v=0;v<2;++v)for(unsigned k=0;k<16;++k) {
                const unsigned full=u+16*k;const size_t loc=a*N+full*256+z;
                for(unsigned i=0;i<8;++i)for(unsigned j=0;j<4;++j) {
                    const U value=rows[(i*4+j)*2+v][loc],identity=rows[(8*4+j)*2+v][loc];
                    A[v*16+k][i*4+j]=value;
                    A[v*16+k][(i+8)*4+j]=sub(i?mul(powers[a][full][i],identity,p):identity,
                                                            mul(powers[a][full][8],value,p),p);
                }
            }
            for(unsigned br=0;br<2;++br)for(unsigned bc=0;bc<4;++bc)for(unsigned i=0;i<8;++i)for(unsigned j=0;j<8;++j) {
                const unsigned rr=br*16+i,cc=bc*16+j;
                const U aa=A[rr][cc],ab=A[rr][cc+8],ac=A[rr+8][cc],ad=A[rr+8][cc+8];
                const U values[]={add(aa,ad,p),add(ac,ad,p),aa,ad,add(aa,ab,p),sub(ac,aa,p),sub(ab,ad,p)};
                for(unsigned leaf=0;leaf<7;++leaf) {
                    const size_t offset=((coord*8+br*4+bc)*7+leaf)*64+i*8+j;
                    result->data[offset]=values[leaf];
                    if(arm)result->data[LEAF_WORDS+offset]=fast_quotient(values[leaf],p);
                }
            }
        }
        return result.release();
    }catch(const std::exception& e){error_text=e.what();return nullptr;}
}
extern "C" void jet_matrix_destroy(void* handle){delete static_cast<Cache*>(handle);}
extern "C" const U* jet_matrix_data(void* handle){return handle?static_cast<Cache*>(handle)->data.data():nullptr;}
extern "C" size_t jet_matrix_words(void* handle){return handle?static_cast<Cache*>(handle)->data.size():0;}

template<bool Fixed> static void apply(const Cache& cache,const U* const* input,U* const* output,unsigned B) {
    U D[64][16],C[32][16],right[7][64],products[7][64];
    for(unsigned a=0;a<3;++a)for(unsigned u=0;u<16;++u)for(unsigned z=0;z<256;++z) {
        const U p=primes[a];const size_t coord=a*4096+u*256+z;
        for(unsigned i=0;i<16;++i)for(unsigned j=0;j<4;++j)for(unsigned b=0;b<16;++b)
            D[i*4+j][b]=b<B?input[b*4+j][a*N+i*4096+u*256+z]:0;
        for(auto& row:C)for(U& x:row)x=0;
        for(unsigned bc=0;bc<4;++bc) {
            for(unsigned i=0;i<8;++i)for(unsigned j=0;j<8;++j) {
                const U aa=D[bc*16+i][j],ab=D[bc*16+i][j+8],ac=D[bc*16+i+8][j],ad=D[bc*16+i+8][j+8];
                const size_t k=i*8+j;
                right[0][k]=add(aa,ad,p);right[1][k]=aa;right[2][k]=sub(ab,ad,p);right[3][k]=sub(ac,aa,p);
                right[4][k]=ad;right[5][k]=add(aa,ab,p);right[6][k]=add(ac,ad,p);
            }
            for(unsigned br=0;br<2;++br) {
                for(unsigned leaf=0;leaf<7;++leaf) {
                    const size_t offset=((coord*8+br*4+bc)*7+leaf)*64;
                    const U* left=cache.data.data()+offset;
                    const U* quot=Fixed?cache.data.data()+LEAF_WORDS+offset:nullptr;
                    for(unsigned i=0;i<8;++i) {
                        for(unsigned j=0;j<8;++j)
                            products[leaf][i*8+j]=Fixed?shoup(right[leaf][j],left[i*8],quot[i*8],p):mul(right[leaf][j],left[i*8],p);
                        for(unsigned k=1;k<8;++k) {
                            const U w=left[i*8+k],wq=Fixed?quot[i*8+k]:0;
                            #pragma GCC unroll 8
                            for(unsigned j=0;j<8;++j) {
                                const U value=Fixed?shoup(right[leaf][k*8+j],w,wq,p):mul(right[leaf][k*8+j],w,p);
                                products[leaf][i*8+j]=add(products[leaf][i*8+j],value,p);
                            }
                        }
                    }
                }
                for(unsigned i=0;i<8;++i)for(unsigned j=0;j<8;++j) {
                    const unsigned t=i*8+j;const U p1=products[0][t],p2=products[1][t],p3=products[2][t],p4=products[3][t],p5=products[4][t],p6=products[5][t],p7=products[6][t];
                    C[br*16+i][j]=add(C[br*16+i][j],add(sub(add(p1,p4,p),p5,p),p7,p),p);
                    C[br*16+i][j+8]=add(C[br*16+i][j+8],add(p3,p5,p),p);
                    C[br*16+i+8][j]=add(C[br*16+i+8][j],add(p2,p4,p),p);
                    C[br*16+i+8][j+8]=add(C[br*16+i+8][j+8],add(add(sub(p1,p2,p),p3,p),p6,p),p);
                }
            }
        }
        for(unsigned v=0;v<2;++v)for(unsigned k=0;k<16;++k)for(unsigned b=0;b<B;++b)
            output[2*b+v][a*N+(u+16*k)*256+z]=C[v*16+k][b];
    }
}
extern "C" int jet_matrix_apply(void* handle,const U* const* input,unsigned input_count,size_t words,U* const* output,unsigned output_count,unsigned B) {
    if(!handle||!input||!output||B<1||B>16||input_count!=4*B||output_count!=2*B||words!=WORDS)return 1;
    const Cache& cache=*static_cast<Cache*>(handle);
    for(unsigned i=0;i<input_count;++i)if(!input[i])return 1;
    for(unsigned i=0;i<output_count;++i) {
        if(!output[i])return 1;
        if(overlap(output[i],WORDS,cache.data.data(),cache.data.size()))return 2;
        for(unsigned j=0;j<i;++j)if(overlap(output[i],WORDS,output[j],WORDS))return 2;
        for(unsigned j=0;j<input_count;++j)if(overlap(output[i],WORDS,input[j],WORDS))return 2;
    }
    for(unsigned b=0;b<input_count;++b)for(unsigned a=0;a<3;++a)for(size_t i=0;i<N;++i)
        if(input[b][a*N+i]>=primes[a])return 3;
    if(cache.arm)apply<true>(cache,input,output,B);else apply<false>(cache,input,output,B);
    return 0;
}
extern "C" int jet_matrix_mul_check(const U* a,const U* b,U* out,size_t n,unsigned channel,unsigned arm) {
    if(!a||!b||!out||channel>2||arm>1||n>1000000)return 1;
    if(overlap(out,n,a,n)||overlap(out,n,b,n))return 2;
    const U p=primes[channel];
    for(size_t i=0;i<n;++i)if(a[i]>=p||b[i]>=p)return 3;
    for(size_t i=0;i<n;++i)out[i]=arm?shoup(a[i],b[i],U((Wide(b[i])<<64)/p),p):mul(a[i],b[i],p);
    return 0;
}
// Deterministic public test fixtures only; never used for keys or encryption.
extern "C" int jet_matrix_fixture(U* out,size_t words,unsigned limbs,U salt) {
    if(!out||limbs<1||limbs>3||words!=limbs*N)return 1;
    U state=salt;
    for(unsigned a=0;a<limbs;++a)for(size_t i=0;i<N;++i) {
        U z=(state+=0x9e3779b97f4a7c15ULL);
        z=(z^(z>>30))*0xbf58476d1ce4e5b9ULL;z=(z^(z>>27))*0x94d049bb133111ebULL;z^=z>>31;
        out[a*N+i]=z%primes[a];
    }
    return 0;
}

extern "C" int jet_fast_quotient_check(const U* input,U* output,size_t n,U p) {
    const U base=U(1)<<60;
    if(!input||!output||n>1000000||p>base||p<=base-(U(1)<<31))return 1;
    if(overlap(input,n,output,n))return 2;
    for(size_t i=0;i<n;++i)if(input[i]>=p)return 3;
    for(size_t i=0;i<n;++i)output[i]=fast_quotient(input[i],p);
    return 0;
}
