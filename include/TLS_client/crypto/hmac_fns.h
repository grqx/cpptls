#ifndef TLS_CLIENT_CRYPTO_HMAC_FNS_H
#define TLS_CLIENT_CRYPTO_HMAC_FNS_H

#include <TLS_client/tls_types.h>
#include <TLS_client/macros.h>
#include <TLS_client/crypto/hash.h>
#include <TLS_client/crypto/hash/sha1.h>

struct MACInfo {
    size_t macLength;
    size_t macKeyLength;
    HashInfo MACHashInfo;
};

template<typename HashAlgo>
IMMEDIATE_EVAL_FN
HMAC_hashFnType makeHMACHashFn() {
    return [](HMAC_hashFnArgsType args) {
        return hmac(
            args.secret,
            args.msg,
            HashAlgo::calculate,
            HashAlgo::BlockSize);
    };
}

std::vector<uint8_t> hmac_sha1(HMAC_hashFnArgsType args);
std::vector<uint8_t> hmac_sha256(HMAC_hashFnArgsType args);

#endif
