#ifndef TLS_CLIENT_CRYPTO_HASH_H
#define TLS_CLIENT_CRYPTO_HASH_H

#include <cstddef>
#include <cstdint>
#include <vector>

typedef std::vector<uint8_t> (*HashFnType)(const std::vector<uint8_t> &);

struct HashInfo {
    HashFnType hashFn;
    size_t blockSizeBytes;
};

#endif
