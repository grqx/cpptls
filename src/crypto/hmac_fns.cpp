#include <TLS_client/crypto/hmac_fns.h>
#include <TLS_client/macros.h>
#include <TLS_client/tls_memory.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {
DEPRECATION_START
std::vector<uint8_t> hmac_sha1(const HMAC_hashFnArgsType &args)
{
    std::vector<uint8_t> result(EVP_MAX_MD_SIZE);
    size_t result_len = 0;

    EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) throw std::runtime_error("Failed to fetch HMAC EVP_MAC");
    unique_ptr_with_deleter<EVP_MAC> mac_deleter{mac, EVP_MAC_free};

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) throw std::runtime_error("Failed to create EVP_MAC_CTX");
    unique_ptr_with_deleter<EVP_MAC_CTX> ctx_deleter{ctx, EVP_MAC_CTX_free};

    char hashName[] = "SHA1";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("digest", hashName, 0),
                           OSSL_PARAM_construct_end()};

    if (EVP_MAC_init(ctx, args.secret.data(), args.secret.size(), params) != 1) {
        throw std::runtime_error("Failed to initialise EVP_MAC_CTX");
    }

    if (EVP_MAC_update(ctx, args.msg.data(), args.msg.size()) != 1) {
        throw std::runtime_error("Failed to update HMAC");
    }

    if (EVP_MAC_final(ctx, result.data(), &result_len, result.size()) != 1) {
        throw std::runtime_error("Failed to finalise HMAC");
    }

    result.resize(result_len);
    return result;
}
DEPRECATION_END
};  // namespace

DEPRECATION_START
std::vector<uint8_t> hmac_sha256(HMAC_hashFnArgsType args)
{
    DISABLE_DEPRECATION_WARNING_START
    std::vector<uint8_t> ret(EVP_MAX_MD_SIZE);
    unsigned int result_len = 0;

    unique_ptr_with_deleter<HMAC_CTX> hmacCtx{HMAC_CTX_new(), HMAC_CTX_free};

    if (HMAC_Init_ex(hmacCtx.get(), args.secret.data(), static_cast<int>(args.secret.size()),
                     EVP_sha256(), nullptr) != 1 ||
        HMAC_Update(hmacCtx.get(), args.msg.data(), args.msg.size()) != 1 ||
        HMAC_Final(hmacCtx.get(), ret.data(), &result_len) != 1) {
        throw std::runtime_error("Failed to compute HMAC-SHA256");
    }
    ret.resize(result_len);
    return ret;
    DISABLE_DEPRECATION_WARNING_END
}
DEPRECATION_END

MACInfo getMACInfo(const CipherSuite &cs)
{
    if (cs == CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA)  // SHA
        return {hmac_sha1, 20, 20};
    UNREACHABLE;
}

DEPRECATION_START
HMAC_hashFnType decideHMACAlgo(const CipherSuite &cs)
{
    return getMACInfo(cs).algo;
}
DEPRECATION_END
