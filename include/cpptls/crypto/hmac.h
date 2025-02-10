#ifndef LIBCPPTLS_CRYPTO_HMAC_H
#define LIBCPPTLS_CRYPTO_HMAC_H

#include <cpptls/export.h>
#include <cpptls/crypto/hash.h>
#include <cpptls/macros.h>

#include <cstddef>
#include <cstdint>
#include <vector>

struct LIBCPPTLS_API HMAC_hashFnArgsType {
    const std::vector<uint8_t>& secret;
    const std::vector<uint8_t>& msg;
};

typedef std::vector<uint8_t> (*HMAC_hashFnType)(HMAC_hashFnArgsType);

LIBCPPTLS_API
std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message,
                          const HashInfo&);

template <typename HashAlgoType>
IMMEDIATE_EVAL_FN HMAC_hashFnType makeHMACHashFn()
{
    return [](HMAC_hashFnArgsType args) {
        return hmac(args.secret, args.msg, {HashAlgoType::calculate, HashAlgoType::BlockSize});
    };
}

#endif
