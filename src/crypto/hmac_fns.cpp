#include <TLS_client/crypto/hmac_fns.h>
#include <TLS_client/macros.h>
#include <TLS_client/tls_memory.h>
#include <TLS_client/crypto/hmac.h>
#include <TLS_client/crypto/hash/sha256.h>
#include <TLS_client/crypto/hash/sha1.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

std::vector<uint8_t> hmac_sha1(HMAC_hashFnArgsType args)
{
    return hmac(args.secret, args.msg, SHA1_calculate, 64);
}

std::vector<uint8_t> hmac_sha256(HMAC_hashFnArgsType args)
{
    return hmac(args.secret, args.msg, SHA256::calculate, 64);
}
