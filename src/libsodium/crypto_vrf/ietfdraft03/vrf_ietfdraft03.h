#ifndef vrf_ietfdraft03_H
#define vrf_ietfdraft03_H
#include "private/ed25519_ref10.h"
#include "crypto_hash_sha512.h"

static const unsigned char SUITE = 0x04;
static const unsigned char ONE = 0x01;
static const unsigned char TWO = 0x02;
static const unsigned char THREE = 0x03;


/* 2^252+27742317777372353535851937790883648493 */
static const unsigned char L[] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
        0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static void
sc25519_negate(unsigned char neg[32], const unsigned char s[32])
{
    unsigned char t_[64];
    unsigned char s_[64];

    memset(t_, 0, sizeof t_);
    memset(s_, 0, sizeof s_);
    memcpy(t_ + 32, L, 32);
    memcpy(s_, s, 32);
    sodium_sub(t_, s_, sizeof t_);
    sc25519_reduce(t_);
    memcpy(neg, t_, 32);
}


/* Hash a message to a curve point using Elligator2.
 * Specified in VRF draft spec section 5.4.1.2.
 * The actual elligator2 implementation is ge25519_from_uniform.
 * Runtime depends only on alphalen (the message length)
 */
static void
vrf_ietfdraft03_hash_to_curve_elligator2_25519(unsigned char H_string[32],
						const ge25519_p3 *Y_point,
						const unsigned char *alpha,
						const unsigned long long alphalen)
{
    crypto_hash_sha512_state hs;
    unsigned char Y_string[32], r_string[64];

    ge25519_p3_tobytes(Y_string, Y_point);

    /* r = first 32 bytes of SHA512(suite || 0x01 || Y || alpha) */
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &ONE, 1);
    crypto_hash_sha512_update(&hs, Y_string, 32);
    crypto_hash_sha512_update(&hs, alpha, alphalen);
    crypto_hash_sha512_final(&hs, r_string);

    r_string[31] &= 0x7f; /* clear sign bit */
    ge25519_from_uniform(H_string, r_string); /* elligator2 */
}

#endif
