#ifndef LIBCPPTLS_CRYPTO_HMAC_FNS_H
#define LIBCPPTLS_CRYPTO_HMAC_FNS_H

#include <cpptls/crypto/hash.h>

struct LIBCPPTLS_API MACInfo {
    size_t macLength;
    size_t macKeyLength;
    HashInfo MACHashInfo;
};

#endif
