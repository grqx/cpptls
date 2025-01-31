#ifndef TLS_CLIENT_CRYPTO_CIPHER_SUITE_H
#define TLS_CLIENT_CRYPTO_CIPHER_SUITE_H

#include <TLS_client/crypto/bulk.h>
#include <TLS_client/crypto/hash.h>
#include <TLS_client/crypto/mac.h>
#include <TLS_client/tls_types.h>

struct KexInfo {
};
struct CipherSuiteInfo {
    KexInfo ki;
    CipherInfo ci;
    MACInfo mi;
    HashInfo PRFHashInfo;
    size_t verifyDataLength = 12;
};

CipherSuiteInfo getCipherSuiteInfo(const CipherSuite &cipherSuite);

#endif