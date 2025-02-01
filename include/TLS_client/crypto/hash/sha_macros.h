#ifndef TLS_CLIENT_CRYPTO_HASH_SHA_MACROS_H
#define TLS_CLIENT_CRYPTO_HASH_SHA_MACROS_H

#define ROTR(x, n) (((x) >> n) | ((x) << (sizeof(x) * 8 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define MAKE_S(x, a, b, c) (ROTR((x), (a)) ^ ROTR((x), (b)) ^ ROTR((x), (c)))
#define MAKE_s(x, a, b, c) (ROTR((x), (a)) ^ ROTR((x), (b)) ^ ((x) >> (c)))

#endif
