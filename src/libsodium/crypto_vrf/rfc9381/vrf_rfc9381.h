#ifndef vrf_rfc9381_H
#define vrf_rfc9381_H
#include "private/ed25519_ref10.h"
#include "crypto_hash_sha512.h"

static const unsigned char SUITE = 0x04; /* ECVRF-ED25519-SHA512-ELL2 */

static const unsigned char ZERO = 0x00;
static const unsigned char TWO = 0x02;
static const unsigned char THREE = 0x03;


// Some helpers for both proving and verifying

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
    memcpy(t_ + 32, L,
           32);
    memcpy(s_, s, 32);
    sodium_sub(t_, s_, sizeof t_);
    sc25519_reduce(t_);
    memcpy(neg, t_, 32);
}

static int
_ECVRF_encode_to_curve_h2c_suite(unsigned char H_string[32],
                                const unsigned char Y_string[32],
                                unsigned char* alpha, unsigned long long alphalen
                                )
{
    const char* ctx = "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\4";

    const size_t n = 1;
    unsigned char h[64];
    unsigned char h_be[2U * 48U];
    size_t        j;

    const size_t h_len = 48U;

    crypto_hash_sha512_state st;
    const unsigned char      empty_block[128U] = { 0 };
    unsigned char            u0[64];
    unsigned char            ux[64] = { 0 };
    unsigned char            t[3] = { 0U, (unsigned char) h_len, 0U};
    unsigned char            ctx_len_u8;
    size_t                   ctx_len = ctx != NULL ? strlen(ctx) : 0U;

    ctx_len_u8 = (unsigned char) ctx_len;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, empty_block, sizeof empty_block);
    crypto_hash_sha512_update(&st, Y_string, 32);
    crypto_hash_sha512_update(&st, alpha, alphalen);
    crypto_hash_sha512_update(&st, t, 3U);
    crypto_hash_sha512_update(&st, (const unsigned char *) ctx, ctx_len);
    crypto_hash_sha512_update(&st, &ctx_len_u8, 1U);
    crypto_hash_sha512_final(&st, u0);

    //for (i = 0U; i < h_len; i += 64) {
        for (j = 0U; j < 64; j++) {
            ux[j] ^= u0[j];
        }
        t[2]++;
        crypto_hash_sha512_init(&st);
        crypto_hash_sha512_update(&st, ux, 64);
        crypto_hash_sha512_update(&st, &t[2], 1U);
        crypto_hash_sha512_update(&st, (const unsigned char *) ctx, ctx_len);
        crypto_hash_sha512_update(&st, &ctx_len_u8, 1U);
        crypto_hash_sha512_final(&st, ux);
        memcpy(&h_be[0], ux, h_len >= (sizeof ux) ? (sizeof ux) : h_len);
    // }
    // if (core_h2c_string_to_hash(h_be, n * HASH_GE_L, ctx, msg, msg_len,
    //                             hash_alg) != 0) {
    //     return -1;
    // }

    for (j = 0U; j < 48; j++) {
        h[j] = h_be[48 - 1U - j];
    }
    memset(&h[j], 0, (sizeof h) - j);
    ge25519_from_hash(H_string, h);
    return 0;
}

// /*
//  Variable time double scalar multiplication with variable bases
//  r = a * A + b * B
//  where a = a[0]+256*a[1]+...+256^31 a[31].
//  and b = b[0]+256*b[1]+...+256^31 b[31].

//  If a null pointer is passed as an argument for B, the function uses
//  the precomputed values of the base point for the scalar multiplication.

//  Only used for ed25519 and VRF verification.
//  */

// static void
// _ge25519_double_scalarmult_vartime(ge25519_p2 *r, const unsigned char *a,
//                                            const ge25519_p3 *A, const unsigned char *b,
//                                            const ge25519_p3 *B)
// {
//     signed char    aslide[256];
//     signed char    bslide[256];
//     ge25519_cached Ai[8];
//     ge25519_p1p1   t;
//     ge25519_p3     u;
//     int            i;

//     slide_vartime(aslide, a);
//     slide_vartime(bslide, b);

//     point_precomputation(Ai, A);

//     ge25519_p2_0(r);

//     for (i = 255; i >= 0; --i) {
//         if (aslide[i] || bslide[i]) {
//             break;
//         }
//     }

//     for (; i >= 0; --i) {
//         ge25519_p2_dbl(&t, r);

//         if (aslide[i] > 0) {
//             ge25519_p1p1_to_p3(&u, &t);
//             ge25519_add_cached(&t, &u, &Ai[aslide[i] / 2]);
//         } else if (aslide[i] < 0) {
//             ge25519_p1p1_to_p3(&u, &t);
//             ge25519_sub_cached(&t, &u, &Ai[(-aslide[i]) / 2]);
//         }

//         if (B == NULL) {
//             static const ge25519_precomp Bi[8] = {
// #ifdef HAVE_TI_MODE
// # include "fe_51/base2.h"
// #else
// # include "fe_25_5/base2.h"
// #endif
//             };
//             if (bslide[i] > 0) {
//                 ge25519_p1p1_to_p3(&u, &t);
//                 ge25519_add_precomp(&t, &u, &Bi[bslide[i] / 2]);
//             } else if (bslide[i] < 0) {
//                 ge25519_p1p1_to_p3(&u, &t);
//                 ge25519_sub_precomp(&t, &u, &Bi[(-bslide[i]) / 2]);
//             }
//         } else {
//             ge25519_cached Bi[8];
//             point_precomputation(Bi, B);
//             if (bslide[i] > 0) {
//                 ge25519_p1p1_to_p3(&u, &t);
//                 ge25519_add_cached(&t, &u, &Bi[bslide[i] / 2]);
//             } else if (bslide[i] < 0) {
//                 ge25519_p1p1_to_p3(&u, &t);
//                 ge25519_sub_cached(&t, &u, &Bi[(-bslide[i]) / 2]);
//             }
//         }

//         ge25519_p1p1_to_p2(r, &t);
//     }
// }


#endif
