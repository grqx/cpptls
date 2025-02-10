#ifndef LIBCPPTLS_CRYPTO_CIPHER_SUITE_H
#define LIBCPPTLS_CRYPTO_CIPHER_SUITE_H

#include <cpptls/export.h>
#include <cpptls/crypto/bulk.h>
#include <cpptls/crypto/hash.h>
#include <cpptls/crypto/mac.h>

enum class CipherSuite : uint16_t {
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
};

struct LIBCPPTLS_API KexInfo {
};

struct LIBCPPTLS_API CipherSuiteInfo {
    KexInfo ki;
    CipherInfo ci;
    MACInfo mi;
    HashInfo PRFHashInfo;
    size_t verifyDataLength = 12;
};

LIBCPPTLS_API
CipherSuiteInfo getCipherSuiteInfo(const CipherSuite &cipherSuite);

#endif