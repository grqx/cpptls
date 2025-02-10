#include <cpptls/crypto/bulk/aes.h>
#include <cpptls/crypto/cipher_suite.h>
#include <cpptls/crypto/hash/sha1.h>
#include <cpptls/crypto/hash/sha256.h>
#include <cpptls/crypto/hash/sha512.h>
#include <cpptls/macros.h>

CipherSuiteInfo getCipherSuiteInfo(const CipherSuite &cipherSuite)
{
    constexpr static KexInfo RSA_KI{};

    constexpr static auto AES_128_CBC = CipherInfo(
        encryptAES_128_CBC, decryptAES_128_CBC, 16, 16, 16, 16
    );
    constexpr static auto AES_256_CBC = CipherInfo(
        encryptAES_256_CBC, decryptAES_256_CBC, 32, 16, 16, 16
    );
    constexpr static auto AES_128_GCM = CipherInfo(
        encryptAES_128_GCM, decryptAES_128_GCM, 16, 8, 4
    );

    constexpr static MACInfo SHA1{
        20,
        20,
        SHA1_hi,
    };
    constexpr static MACInfo SHA256{
        32,
        32,
        HashAlgo_SHA256::hi,
    };
    // NOTE: when mi == SHA384 or cipherSuite ends with _SHA384, PRFHashInfo == SHA384
    constexpr static MACInfo SHA384{
        48,
        64,
        HashAlgo_SHA384::hi,
    };

    if (cipherSuite == CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA)
        return {RSA_KI, AES_128_CBC, SHA1, SHA256.MACHashInfo};
    else if (cipherSuite == CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256)
        return {RSA_KI, AES_128_CBC, SHA256, SHA256.MACHashInfo};
    else if (cipherSuite == CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA)
        return {RSA_KI, AES_256_CBC, SHA1, SHA256.MACHashInfo};
    else if (cipherSuite == CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256)
        return {RSA_KI, AES_256_CBC, SHA256, SHA256.MACHashInfo};
    else if (cipherSuite == CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256)
        return {RSA_KI, AES_128_GCM, SHA256, SHA256.MACHashInfo};
    UNREACHABLE;
}
