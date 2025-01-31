#include <TLS_client/crypto/hash/sha1.h>
#include <TLS_client/crypto/hash/sha256.h>
#include <TLS_client/crypto/hmac.h>

std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message,
                          const HashFnType& hash_, size_t block_size)
{
    std::vector<uint8_t> key_pad = key;
    if (key_pad.size() > block_size) {
        key_pad = hash_(key_pad);
    }
    key_pad.resize(block_size, 0);

    std::vector<uint8_t> o_key_pad(block_size, 0x5c);
    std::vector<uint8_t> i_key_pad(block_size, 0x36);

    for (size_t i = 0; i < block_size; ++i) {
        o_key_pad[i] ^= key_pad[i];
        i_key_pad[i] ^= key_pad[i];
    }

    std::vector<uint8_t> inner = i_key_pad;
    inner.insert(inner.end(), message.begin(), message.end());
    std::vector<uint8_t> inner_hash = hash_(inner);

    std::vector<uint8_t> outer = o_key_pad;
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return hash_(outer);
}
