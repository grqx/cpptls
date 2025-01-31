#ifndef TLS_CLIENT_CRYPTO_HASH_SHA1_H
#define TLS_CLIENT_CRYPTO_HASH_SHA1_H

#include <cstdint>
#include <cstddef>
#include <vector>

std::vector<uint8_t> SHA1_calculate(const std::vector<uint8_t> &data);
class HashAlgo_SHA1 {
public:
    static std::vector<uint8_t> calculate(const std::vector<uint8_t> &data) { return SHA1_calculate(data); }
    static constexpr size_t BlockSize = 64;
};

#endif
