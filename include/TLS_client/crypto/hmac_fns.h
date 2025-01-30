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
DEPRECATION_START
std::vector<uint8_t> hmac_sha256(HMAC_hashFnArgsType args);
HMAC_hashFnType decideHMACAlgo(const CipherSuite &cs);
DEPRECATION_END

#endif
