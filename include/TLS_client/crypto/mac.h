#ifndef TLS_CLIENT_CRYPTO_HMAC_FNS_H
#define TLS_CLIENT_CRYPTO_HMAC_FNS_H

#include <TLS_client/crypto/hash.h>

struct MACInfo {
    size_t macLength;
    size_t macKeyLength;
    HashInfo MACHashInfo;
};

#endif
