#ifndef TLS_CLIENT_CRYPTO_SYMENC_FNS_H
#define TLS_CLIENT_CRYPTO_SYMENC_FNS_H

#include <TLS_client/macros.h>
#include <TLS_client/tls_memory.h>
#include <TLS_client/tls_types.h>
#include <openssl/evp.h>

#include <cstdint>
#include <vector>

namespace ChatGPT4o {
std::vector<uint8_t> encryptAES_128_CBC(symEncFnArgsType args)
{
    if (args.key.size() != 16) {
        throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    }
    if (args.iv.size() != 16) {
        throw std::invalid_argument("IV size must be 16 bytes for AES-128-CBC");
    }
    if (args.data.size() % 16 != 0 || args.data.size() == 0) {
        throw std::invalid_argument(
            "Data size must be non-zero and a multiple of "
            "16 bytes for AES-128-CBC");
    }

    // Define a unique_ptr with a custom deleter for EVP_CIPHER_CTX
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(
        EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); });

    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, args.key.data(),
                           args.iv.data()) != 1) {
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    // Enable padding (optional, enabled by default in OpenSSL)
    if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) {
        throw std::runtime_error("EVP_CIPHER_CTX_set_padding failed");
    }

    // Prepare output buffer
    int outlen = 0;
    std::vector<uint8_t> ciphertext(args.data.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

    // Perform the encryption
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outlen, args.data.data(),
                          args.data.size()) != 1) {
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int total_len = outlen;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outlen, &outlen) != 1) {
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    total_len += outlen;

    // Resize the ciphertext buffer to the actual size
    ciphertext.resize(total_len);

    return ciphertext;
}

std::vector<uint8_t> decryptAES_128_CBC(symDecFnArgsType args)
{
    if (args.key.size() != 16) {
        throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    }
    if (args.iv.size() != 16) {
        throw std::invalid_argument("IV size must be 16 bytes for AES-128-CBC");
    }
    if (args.encryptedData.size() % 16 != 0 || args.encryptedData.size() == 0) {
        throw std::invalid_argument(
            "Data size must be non-zero and a multiple of "
            "16 bytes for AES-128-CBC");
    }

    // Define a unique_ptr with a custom deleter for EVP_CIPHER_CTX
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(
        EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); });

    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, args.key.data(),
                           args.iv.data()) != 1) {
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    // Enable padding (optional, enabled by default in OpenSSL)
    if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) {
        throw std::runtime_error("EVP_CIPHER_CTX_set_padding failed");
    }

    // Prepare output buffer
    int outlen = 0;
    std::vector<uint8_t> plaintext(args.encryptedData.size() +
                                   EVP_CIPHER_block_size(EVP_aes_128_cbc()));

    // Perform the decryption
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outlen, args.encryptedData.data(),
                          args.encryptedData.size()) != 1) {
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    int total_len = outlen;

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outlen, &outlen) != 1) {
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    total_len += outlen;

    // Resize the plaintext buffer to the actual size
    plaintext.resize(total_len);

    return plaintext;
}
};  // namespace ChatGPT4o

typedef struct {
    symEncFnType encFn;
    symDecFnType decFn;
    int keyMaterial;
    int IVSize;
    // -1 for stream ciphers
    int blockSize;
} CipherInfo;

CipherInfo getCipherInfo(const CipherSuite &cs)
{
    if (cs == CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA)  // AES_128_CBC
        return {ChatGPT4o::encryptAES_128_CBC, ChatGPT4o::decryptAES_128_CBC, 16, 16, 16};
    UNREACHABLE;
}

#endif
