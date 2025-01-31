#ifndef TLS_CLIENT_CRYPTO_HASH_H
#define TLS_CLIENT_CRYPTO_HASH_H

#ifdef TLS_HASH_NEED_ALGO
#include <TLS_client/crypto/hash/sha1.h>
#include <TLS_client/crypto/hash/sha256.h>
#undef TLS_HASH_NEED_ALGO
#endif

#include <cstddef>
#include <functional>
#include <TLS_client/tls_types.h>

struct HashInfo {
    HashFnType hashFn;
    size_t blockSizeBytes;
};

#endif
