#ifndef vrf_ietfdraft03_H
#define vrf_ietfdraft03_H
#include "private/ed25519_ref10.h"
#include "crypto_hash_sha512.h"
#include "vrf_rfc9381.h"


static const unsigned char ONE = 0x01;


/* Hash a message to a curve point using Elligator2.
 * Specified in VRF draft spec section 5.4.1.2.
 * The actual elligator2 implementation is ge25519_from_uniform.
 * Runtime depends only on alphalen (the message length)
 */
static void
_vrf_ietfdraft03_hash_to_curve_elligator2_25519(unsigned char H_string[32],
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
