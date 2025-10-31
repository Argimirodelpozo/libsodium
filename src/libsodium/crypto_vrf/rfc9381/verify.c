#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "crypto_hash_sha512.h"
#include "crypto_vrf_rfc9381.h"
#include "private/ed25519_ref10.h"
#include "vrf_rfc9381.h"
#include "vrf_ietfdraft03.h"
#include "crypto_verify_16.h"

int
crypto_vrf_rfc9381_proof_to_hash(unsigned char *beta,
                                     const unsigned char *pi)
{
    ge25519_p3    Gamma;
    unsigned char gamma_string[32];

    if (ge25519_is_canonical(pi) == 0 ||
        ge25519_frombytes(&Gamma, pi) != 0) {
        return -1;
    }

    if (pi[48 + 31] & 240 &&
        sc25519_is_canonical(pi + 48) == 0) {
        return -1;
    }

    ge25519_clear_cofactor(&Gamma);
    ge25519_p3_tobytes(gamma_string, &Gamma);

    /* beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma) || zero_string ) */
    crypto_hash_sha512_state hs;
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &THREE, 1);
    crypto_hash_sha512_update(&hs, gamma_string, 32);
    crypto_hash_sha512_update(&hs, &ZERO, 1);
    crypto_hash_sha512_final(&hs, beta);

    return 0;
}

int
crypto_vrf_ietfdraft03_proof_to_hash(unsigned char *beta,
                                     const unsigned char *pi)
{
    ge25519_p3    Gamma;
    unsigned char gamma_string[32];

    if (ge25519_is_canonical(pi) == 0 ||
        ge25519_frombytes(&Gamma, pi) != 0) {
        return -1;
    }

    if (pi[48 + 31] & 240 &&
        sc25519_is_canonical(pi + 48) == 0) {
        return -1;
    }

    ge25519_clear_cofactor(&Gamma);
    ge25519_p3_tobytes(gamma_string, &Gamma);

    /* beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma)) */
    crypto_hash_sha512_state hs;
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &THREE, 1);
    crypto_hash_sha512_update(&hs, gamma_string, 32);
    crypto_hash_sha512_final(&hs, beta);

    return 0;
}

static int
vrf_rfc9381_verify(const unsigned char *pi,
           const unsigned char *alpha, unsigned long long alphalen,
           const ge25519_p3 *Y_point)
{
    unsigned char H_string[32], U_string[32], V_string[32], Y_string[32];
    unsigned char cn[32], c[32], s[32];
    unsigned char challenge[64];

    crypto_hash_sha512_state hs;
    ge25519_p2 U; 
    ge25519_p3 V;
    ge25519_p3 v0, v1;
    ge25519_p3     H, Gamma;
    ge25519_p1p1   tmp_p1p1_point;
    ge25519_cached tmp_cached_point;

    ge25519_p3_tobytes(Y_string, Y_point);

    if (ge25519_is_canonical(pi) == 0 ||
        ge25519_frombytes(&Gamma, pi) != 0) {
        return -1;
    }

    memmove(c, pi + 32, 16); /* c = pi[32:48] */
    memmove(s, pi + 48, 32); /* s = pi[48:80] */

    if (s[31] & 240 &&
        sc25519_is_canonical(s) == 0) {
        return -1;
    }

    memset(c + 16, 0, 16);

    _ECVRF_encode_to_curve_h2c_suite(H_string, Y_string, alpha, alphalen);

    ge25519_frombytes(&H, H_string);
    sc25519_negate(cn, c); /* negate scalar c */

    // U = cn * Y_point + s * B, where B is the base point
    ge25519_double_scalarmult_vartime(&U, cn, Y_point, s);

    // V = cn * Gamma + s * H
    ge25519_scalarmult(&v0, cn, &Gamma);
    ge25519_scalarmult(&v1, s, &H);
    ge25519_p3_add(&V, &v0, &v1);

    ge25519_tobytes(U_string, &U);
    ge25519_p3_tobytes(V_string, &V);

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &TWO, 1);
    crypto_hash_sha512_update(&hs, Y_string, 32);
    crypto_hash_sha512_update(&hs, H_string, 32);
    crypto_hash_sha512_update(&hs, pi, 32);
    crypto_hash_sha512_update(&hs, U_string, 32);
    crypto_hash_sha512_update(&hs, V_string, 32);
    crypto_hash_sha512_update(&hs, &ZERO, 1);
    crypto_hash_sha512_final(&hs, challenge);

    return crypto_verify_16(c, challenge);
}

static int
vrf_ietfdraft03_verify(const unsigned char *pi,
           const unsigned char *alpha, unsigned long long alphalen,
           const ge25519_p3 *Y_point)
{
    unsigned char H_string[32], U_string[32], V_string[32], Y_string[32];
    unsigned char cn[32], c[32], s[32];
    unsigned char challenge[64];

    crypto_hash_sha512_state hs;

    ge25519_p2 U; 
    ge25519_p3 V;
    ge25519_p3 v0, v1;

    ge25519_p3     H, Gamma;
    ge25519_p1p1   tmp_p1p1_point;
    ge25519_cached tmp_cached_point;

    ge25519_p3_tobytes(Y_string, Y_point);

    if (ge25519_is_canonical(pi) == 0 ||
        ge25519_frombytes(&Gamma, pi) != 0) {
        return -1;
    }

    memmove(c, pi + 32, 16); /* c = pi[32:48] */
    memmove(s, pi + 48, 32); /* s = pi[48:80] */

    if (s[31] & 240 &&
        sc25519_is_canonical(s) == 0) {
        return -1;
    }
    memset(c + 16, 0, 16);

    _vrf_ietfdraft03_hash_to_curve_elligator2_25519(H_string, Y_point, alpha, alphalen);

    ge25519_frombytes(&H, H_string);
    sc25519_negate(cn, c); /* negate scalar c */

    // U = cn * Y_point + s * B, where B is the base point
    ge25519_double_scalarmult_vartime(&U, cn, Y_point, s);

    // V = cn * Gamma + s * H
    ge25519_scalarmult(&v0, cn, &Gamma);
    ge25519_scalarmult(&v1, s, &H);
    ge25519_p3_add(&V, &v0, &v1);

    ge25519_tobytes(U_string, &U);
    ge25519_p3_tobytes(V_string, &V);

    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &TWO, 1);
    crypto_hash_sha512_update(&hs, H_string, 32);
    crypto_hash_sha512_update(&hs, pi, 32);
    crypto_hash_sha512_update(&hs, U_string, 32);
    crypto_hash_sha512_update(&hs, V_string, 32);
    crypto_hash_sha512_final(&hs, challenge);

    return crypto_verify_16(c, challenge);
}

int
crypto_vrf_rfc9381_verify(unsigned char *output,
                              const unsigned char *pk,
                              const unsigned char *proof,
                              const unsigned char *msg, const unsigned long long msglen)
{
    ge25519_p3 Y;
    if (ge25519_frombytes(&Y, pk) == 0 && ge25519_has_small_order(&Y) == 0 &&
    ge25519_is_canonical(pk) == 1 && (vrf_rfc9381_verify(proof, msg, msglen, &Y) == 0)) {
        return crypto_vrf_rfc9381_proof_to_hash(output, proof);
    } else {
        return -1;
    }
}

int
crypto_vrf_ietfdraft03_verify(unsigned char *output,
                              const unsigned char *pk,
                              const unsigned char *proof,
                              const unsigned char *msg, const unsigned long long msglen)
{
    ge25519_p3 Y;
    if (ge25519_frombytes(&Y, pk) == 0 && ge25519_has_small_order(&Y) == 0 &&
    ge25519_is_canonical(pk) == 1 && (vrf_ietfdraft03_verify(proof, msg, msglen, &Y) == 0)) {
        return crypto_vrf_ietfdraft03_proof_to_hash(output, proof);
    } else {
        return -1;
    }
}