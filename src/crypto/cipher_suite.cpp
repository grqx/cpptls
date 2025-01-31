#include <TLS_client/crypto/bulk/aes.h>
#include <TLS_client/crypto/cipher_suite.h>
#include <TLS_client/crypto/hash/sha1.h>
#include <TLS_client/crypto/hash/sha256.h>

CipherSuiteInfo getCipherSuiteInfo(const CipherSuite &cipherSuite)
{
    CipherSuiteInfo ret;
    ret.PRFHashInfo.hashFn = SHA256::calculate;
    ret.PRFHashInfo.blockSizeBytes = 64;

    constexpr static KexInfo RSA_KI{};

    constexpr static CipherInfo AES_128_CBC{
        encryptAES_128_CBC, decryptAES_128_CBC, 16, 16, 16,
    };

    constexpr static MACInfo SHA1{
        20,
        20,
        {HashAlgo_SHA1::calculate, HashAlgo_SHA1::BlockSize},
    };

    if (cipherSuite == CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA) {
        ret.ki = {RSA_KI};
        ret.ci = {AES_128_CBC};
        ret.mi = {SHA1};
    }
    return ret;
}