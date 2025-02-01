#include <TLS_client/crypto/bulk/aes.h>
#include <TLS_client/crypto/cipher_suite.h>
#include <TLS_client/crypto/hash/sha1.h>
#include <TLS_client/crypto/hash/sha256.h>
#include <TLS_client/crypto/hash/sha512.h>
#include <TLS_client/macros.h>

CipherSuiteInfo getCipherSuiteInfo(const CipherSuite &cipherSuite)
{
    constexpr static KexInfo RSA_KI{};

    constexpr static CipherInfo AES_128_CBC{
        encryptAES_128_CBC, decryptAES_128_CBC, 16, 16, 16,
    };
    constexpr static CipherInfo AES_256_CBC{
        encryptAES_256_CBC, decryptAES_256_CBC, 32, 16, 16,
    };

    constexpr static MACInfo SHA1{
        20,
        20,
        {HashAlgo_SHA1::calculate, HashAlgo_SHA1::BlockSize},
    };
    constexpr static MACInfo SHA256{
        32,
        32,
        {HashAlgo_SHA256::calculate, HashAlgo_SHA256::BlockSize},
    };
    // NOTE: when mi == SHA384, PRFHashInfo == SHA384
    constexpr static MACInfo SHA384{
        48,
        64,
        {HashAlgo_SHA384::calculate, HashAlgo_SHA384::BlockSize},
    };

    CipherSuiteInfo ret;
    ret.PRFHashInfo = SHA256.MACHashInfo;
    if (cipherSuite == CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA) {
        ret.ki = RSA_KI;
        ret.ci = AES_128_CBC;
        ret.mi = SHA1;
    } else if (cipherSuite == CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256) {
        ret.ki = RSA_KI;
        ret.ci = AES_128_CBC;
        ret.mi = SHA256;
    } else if (cipherSuite == CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA) {
        ret.ki = RSA_KI;
        ret.ci = AES_256_CBC;
        ret.mi = SHA1;
    } else if (cipherSuite == CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256) {
        ret.ki = RSA_KI;
        ret.ci = AES_256_CBC;
        ret.mi = SHA256;
    } else
        UNREACHABLE;
    return ret;
}