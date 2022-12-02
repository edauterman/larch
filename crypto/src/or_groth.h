#ifndef _OR_GROTH_H_
#define _OR_GROTH_H_

class OrProof {
    public:
        OrProof(BIGNUM **c_l, BIGNUM **c_a, BIGNUM **c_b, BIGNUM **c_d, BIGNUM **f, BIGNUM **z_a, BIGNUM **z_b, BIGNUM *z_d, int len, int log_len);
        BIGNUM **c_l;
        BIGNUM **c_a;
        BIGNUM **c_b;
        BIGNUM **c_d;
        BIGNUM **f;
        BIGNUM **z_a;
        BIGNUM **z_b;
        BIGNUM *z_d;
        int len;
        int log_len;
}

bool Verify(Params params, OrProof *proof, EC_POINT **cms, int len, int log_len);
OrProof *Prove(Params params, EC_POINT **cms, int idx, int len, int log_len, BIGNUM *open);

#endif
