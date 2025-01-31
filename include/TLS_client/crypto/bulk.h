#ifndef TLS_CLIENT_CRYPTO_BULK_H
#define TLS_CLIENT_CRYPTO_BULK_H

#include <cstdint>
#include <vector>

struct symEncFnArgsType {
    const std::vector<uint8_t> &key;
    const std::vector<uint8_t> &iv;
    const std::vector<uint8_t> &data;
};
typedef std::vector<uint8_t> (*symEncFnType)(symEncFnArgsType args);

struct symDecFnArgsType {
    const std::vector<uint8_t> &key;
    const std::vector<uint8_t> &iv;
    const std::vector<uint8_t> &encryptedData;
};
typedef std::vector<uint8_t> (*symDecFnType)(symDecFnArgsType args);

struct CipherInfo {
    symEncFnType encFn;
    symDecFnType decFn;
    int keyMaterial;
    int IVSize;
    // -1 for stream ciphers
    int blockSize;
};

#endif
