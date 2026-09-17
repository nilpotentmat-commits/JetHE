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
