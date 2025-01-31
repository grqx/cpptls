#ifndef TLS_CLIENT_CRYPTO_HMAC_H
#define TLS_CLIENT_CRYPTO_HMAC_H

#include <TLS_client/crypto/hash.h>
#include <TLS_client/macros.h>

#include <cstddef>
#include <cstdint>
#include <vector>

struct HMAC_hashFnArgsType {
    const std::vector<uint8_t>& secret;
    const std::vector<uint8_t>& msg;
};

typedef std::vector<uint8_t> (*HMAC_hashFnType)(HMAC_hashFnArgsType);

std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message,
                          const HashFnType& hash_, size_t block_size);

template <typename HashAlgoType>
IMMEDIATE_EVAL_FN HMAC_hashFnType makeHMACHashFn()
{
    return [](HMAC_hashFnArgsType args) {
        return hmac(args.secret, args.msg, HashAlgoType::calculate, HashAlgoType::BlockSize);
    };
}

#endif
