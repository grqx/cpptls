#include <cpptls/crypto/hash.h>
#include <cpptls/crypto/hash/sha1.h>
#include <cpptls/crypto/hash/sha256.h>
#include <cpptls/crypto/hmac.h>

std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message,
                          const HashInfo& hi)
{
    std::vector<uint8_t> key_pad = key;
    if (key_pad.size() > hi.blockSizeBytes) {
        key_pad = hi.hashFn(key_pad);
    }
    key_pad.resize(hi.blockSizeBytes, 0);

    std::vector<uint8_t> o_key_pad(hi.blockSizeBytes, 0x5c);
    std::vector<uint8_t> i_key_pad(hi.blockSizeBytes, 0x36);

    for (size_t i = 0; i < hi.blockSizeBytes; ++i) {
        o_key_pad[i] ^= key_pad[i];
        i_key_pad[i] ^= key_pad[i];
    }

    std::vector<uint8_t> inner = i_key_pad;
    inner.insert(inner.end(), message.begin(), message.end());
    std::vector<uint8_t> inner_hash = hi.hashFn(inner);

    std::vector<uint8_t> outer = o_key_pad;
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return hi.hashFn(outer);
}
