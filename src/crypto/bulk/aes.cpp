
#include <TLS_client/crypto/bulk/aes.h>
#include <TLS_client/tls_memory.h>
#include <openssl/evp.h>

#include <stdexcept>

std::vector<uint8_t> encryptAES_128_CBC(symEncFnArgsType args)
{
    if (args.data.empty()) return args.data;
    if (args.key.size() != 16) throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    if (args.iv.size() != 16) throw std::invalid_argument("IV size must be 16 bytes for AES-CBC");
    if (args.data.size() % 16 != 0)
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES");
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), [&](EVP_CIPHER_CTX *ptr) {
        if (ctx) EVP_CIPHER_CTX_free(ptr);
    });
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, args.key.data(),
                           args.iv.data()) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_set_padding failed");
    std::vector<uint8_t> ciphertext(args.data.size());
    int outlen;
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outlen, args.data.data(),
                          args.data.size()) != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outlen, &outlen) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    return ciphertext;
}

std::vector<uint8_t> decryptAES_128_CBC(symDecFnArgsType args)
{
    if (args.encryptedData.empty()) return args.encryptedData;
    if (args.key.size() != 16) throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    if (args.iv.size() != 16) throw std::invalid_argument("IV size must be 16 bytes for AES-CBC");
    if (args.encryptedData.size() % 16 != 0)
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES");
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), [&](EVP_CIPHER_CTX *ptr) {
        if (ctx) EVP_CIPHER_CTX_free(ptr);
    });
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, args.key.data(),
                           args.iv.data()) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_set_padding failed");
    std::vector<uint8_t> plaintext(args.encryptedData.size());
    int outlen;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outlen, args.encryptedData.data(),
                          args.encryptedData.size()) != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outlen, &outlen) != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    return plaintext;
}

std::vector<uint8_t> encryptAES_256_CBC(symEncFnArgsType args)
{
    if (args.data.empty()) return args.data;
    if (args.key.size() != 32) throw std::invalid_argument("Key size must be 32 bytes for AES-256");
    if (args.iv.size() != 16) throw std::invalid_argument("IV size must be 16 bytes for AES-CBC");
    if (args.data.size() % 16 != 0)
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES");
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(
        EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); });
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, args.key.data(),
                           args.iv.data()) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_set_padding failed");
    std::vector<uint8_t> ciphertext(args.data.size());
    int outlen;
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outlen, args.data.data(),
                          args.data.size()) != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outlen, &outlen) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    return ciphertext;
}

std::vector<uint8_t> decryptAES_256_CBC(symDecFnArgsType args)
{
    if (args.encryptedData.empty()) return args.encryptedData;
    if (args.key.size() != 32) throw std::invalid_argument("Key size must be 16 bytes for AES-256");
    if (args.iv.size() != 16) throw std::invalid_argument("IV size must be 16 bytes for AES-CBC");
    if (args.encryptedData.size() % 16 != 0)
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES");
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), [&](EVP_CIPHER_CTX *ptr) {
        if (ctx) EVP_CIPHER_CTX_free(ptr);
    });
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, args.key.data(),
                           args.iv.data()) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_set_padding failed");
    std::vector<uint8_t> plaintext(args.encryptedData.size());
    int outlen;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outlen, args.encryptedData.data(),
                          args.encryptedData.size()) != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outlen, &outlen) != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    return plaintext;
}

// TODO: support AEAD ciphers like AES-GCM
