#include <TLS_client/crypto/hmac_fns.h>
#include <TLS_client/macros.h>
#include <TLS_client/tls_memory.h>
#include <TLS_client/crypto/hmac.h>
#include <TLS_client/crypto/sha256.h>
#include <TLS_client/crypto/hash_fns.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {
std::vector<uint8_t> hmac_sha1(const HMAC_hashFnArgsType &args)
{
    return hmac(args.secret, args.msg, ChatGPT4o::TLS_sha1, 64);
}
};  // namespace

HMAC_hashFnType makeHMACHashFn(const HashFunctionType& hashFn, size_t blockSize)
{
    return [&](HMAC_hashFnArgsType args) {
        return hmac(args.secret, args.msg, hashFn, blockSize);
    };
}

std::vector<uint8_t> hmac_sha256(HMAC_hashFnArgsType args)
{
    return hmac(args.secret, args.msg, SHA256::calculate, 64);
}

MACInfo getMACInfo(const CipherSuite &cs)
{
    if (cs == CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA)  // SHA
        return {hmac_sha1, 20, 20};
    UNREACHABLE;
}
