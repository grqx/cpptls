#ifndef TLS_CLIENT_CRYPTO_HMAC_FNS_H
#define TLS_CLIENT_CRYPTO_HMAC_FNS_H

#include <TLS_client/macros.h>
#include <TLS_client/tls_types.h>

typedef struct {
    HMAC_hashFnType algo;
    int macLength;
    int macKeyLength;
} MACInfo;
MACInfo getMACInfo(const CipherSuite &cs);
HMAC_hashFnType makeHMACHashFn(const HashFunctionType& hashFn, size_t blockSize);
std::vector<uint8_t> hmac_sha256(HMAC_hashFnArgsType args);

#endif
