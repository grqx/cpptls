#include <vector>
#include <string>
#include <functional>
#include <algorithm>
#include <iostream>
#include <openssl/evp.h>

using u8 = uint8_t;
using HashFunction = std::function<std::vector<u8>(const std::vector<u8>&)>;

std::vector<u8> sha256(const std::vector<u8>& data) {
    std::vector<u8> hash(EVP_MD_size(EVP_sha256()));
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash.data(), nullptr);
    EVP_MD_CTX_free(ctx);
    return hash;
}

std::vector<u8> hmac(const std::vector<u8>& key, const std::vector<u8>& message, HashFunction hash, size_t block_size) {
    std::vector<u8> key_pad = key;
    if (key_pad.size() > block_size) {
        key_pad = hash(key_pad);
    }
    key_pad.resize(block_size, 0);
    
    std::vector<u8> o_key_pad(block_size, 0x5c);
    std::vector<u8> i_key_pad(block_size, 0x36);
    
    for (size_t i = 0; i < block_size; ++i) {
        o_key_pad[i] ^= key_pad[i];
        i_key_pad[i] ^= key_pad[i];
    }
    
    std::vector<u8> inner = i_key_pad;
    inner.insert(inner.end(), message.begin(), message.end());
    std::vector<u8> inner_hash = hash(inner);
    
    std::vector<u8> outer = o_key_pad;
    outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
    return hash(outer);
}

void test_hmac() {
    std::vector<u8> key = {'k', 'e', 'y'};
    std::vector<u8> message = {'m', 's', 'g'};
    
    std::vector<u8> result = hmac(key, message, sha256, 64);
    
    std::cout << "HMAC-SHA256 result: ";
    for (u8 byte : result) {
        printf("%02x", byte);
    }
    std::cout << std::endl;
}

int main() {
    test_hmac();
    return 0;
}
