// Public spectral rearrangement only. No context, randomness, keys or HE policy.
#include <cstdint>
extern "C" int jet_terminal_multipliers(const uint64_t* compact, const uint64_t* t,
    uint64_t* signed_even, uint64_t* odd, unsigned length, unsigned limbs) {
    if (!length || length > 256 || (length & (length-1)) || length < 2 || !limbs || limbs > 4) return 1;
    const uint64_t primes[] = {1152921504002872321ULL,1152921503566671361ULL,
                              1152921503264686081ULL,1152921503096916481ULL};
    const unsigned n = length*256, half = n/2;
    for (unsigned a=0;a<limbs;++a) for (unsigned k=0;k<length;++k) for (unsigned b=0;b<256;++b) {
        const unsigned i=a*n+k*256+b, j=a*n+(k%(length/2))*256+b;
        const uint64_t e=compact[j], o=compact[j+half], p=primes[a];
        const uint64_t to=static_cast<unsigned __int128>(t[i])*o%p;
        signed_even[i]=e>=to ? e-to : e+p-to;
        odd[i]=o;
    }
    return 0;
}
