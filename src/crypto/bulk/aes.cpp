
#include <cpptls/crypto/bulk/aes.h>
#include <cpptls/tls_memory.h>
#include <openssl/evp.h>

#include <stdexcept>
#include <algorithm>

std::vector<uint8_t> encryptAES_128_CBC(BlockOrStreamEncFnArgsType args)
{
    if (args.data.empty()) return args.data;
    if (args.key.size() != 16) throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    if (args.iv.size() != 16) throw std::invalid_argument("IV size must be 16 bytes for AES-CBC");
    if (args.data.size() % 16 != 0)
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES");
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX *ptr) {
        if (ptr) EVP_CIPHER_CTX_free(ptr);
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

std::vector<uint8_t> decryptAES_128_CBC(BlockOrStreamDecFnArgsType args)
{
    if (args.encryptedData.empty()) return args.encryptedData;
    if (args.key.size() != 16) throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    if (args.iv.size() != 16) throw std::invalid_argument("IV size must be 16 bytes for AES-CBC");
    if (args.encryptedData.size() % 16 != 0)
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES");
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX *ptr) {
        if (ptr) EVP_CIPHER_CTX_free(ptr);
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

std::vector<uint8_t> encryptAES_256_CBC(BlockOrStreamEncFnArgsType args)
{
    if (args.data.empty()) return args.data;
    if (args.key.size() != 32) throw std::invalid_argument("Key size must be 32 bytes for AES-256");
    if (args.iv.size() != 16) throw std::invalid_argument("IV size must be 16 bytes for AES-CBC");
    if (args.data.size() % 16 != 0)
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES");
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(
        EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX *ptr) { if (ptr) EVP_CIPHER_CTX_free(ptr); });
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

std::vector<uint8_t> decryptAES_256_CBC(BlockOrStreamDecFnArgsType args)
{
    if (args.encryptedData.empty()) return args.encryptedData;
    if (args.key.size() != 32) throw std::invalid_argument("Key size must be 16 bytes for AES-256");
    if (args.iv.size() != 16) throw std::invalid_argument("IV size must be 16 bytes for AES-CBC");
    if (args.encryptedData.size() % 16 != 0)
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES");
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX *ptr) {
        if (ptr) EVP_CIPHER_CTX_free(ptr);
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

std::vector<uint8_t> encryptAES_128_GCM(AEADEncFnArgsType args)
{
    if (args.data.empty())
        return args.data;
    if (args.key.size() != 16)
        throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    if (args.writeIV.size() != 4)
        throw std::invalid_argument("writeIV size must be 4 bytes for AES-GCM");
    if (args.nonceExplicit.size() != 8)
        throw std::invalid_argument("nonceExplicit size must be 8 bytes for AES-GCM");

    // Construct the 12-byte nonce: implicit (writeIV, 4 bytes) || explicit (nonceExplicit, 8 bytes)
    std::vector<uint8_t> nonce(16);
    std::copy(args.writeIV.begin(), args.writeIV.end(), nonce.begin());
    std::copy(args.nonceExplicit.begin(), args.nonceExplicit.end(), nonce.begin() + 4);
    // again, some1 said that 000001 is appended to the nonce to make it 128bit
    int idx = 12;
    nonce[idx++] = 0;
    nonce[idx++] = 0;
    nonce[idx++] = 0;
    nonce[idx++] = 1;

    unique_ptr_with_fnptr_deleter<EVP_CIPHER_CTX> ctx(
        EVP_CIPHER_CTX_new(),
        [](EVP_CIPHER_CTX *ptr) { if (ptr) EVP_CIPHER_CTX_free(ptr); }
    );
    if (!ctx)
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    // Initialise encryption context with AES-128-GCM (key and nonce will be provided subsequently)
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    // Set the IV length to 12 bytes (nonce size)
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");

    // Provide key and IV (nonce)
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, args.key.data(), nonce.data()) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex (key/IV) failed");

    int outlen = 0;
    // Process any additional authenticated data (AAD)
    if (!args.additionalData.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen,
                              args.additionalData.data(), args.additionalData.size()) != 1)
            throw std::runtime_error("EVP_EncryptUpdate (AAD) failed");
    }

    // Allocate output buffer for ciphertext (plaintext size)
    std::vector<uint8_t> ciphertext(args.data.size());
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outlen,
                          args.data.data(), args.data.size()) != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");
    int ciphertext_len = outlen;

    // Finalise encryption (GCM doesn't output additional ciphertext here)
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outlen, &outlen) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    ciphertext_len += outlen;
    // Note: ciphertext_len should equal args.data.size() here

    // Retrieve the 16-byte authentication tag
    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (GET_TAG) failed");

    // Append the tag to the ciphertext
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return ciphertext;
}

std::vector<uint8_t> decryptAES_128_GCM(AEADDecFnArgsType args)
{
    if (args.encryptedData.empty())
        return args.encryptedData;
    if (args.key.size() != 16)
        throw std::invalid_argument("Key size must be 16 bytes for AES-128");
    if (args.readIV.size() != 4)
        throw std::invalid_argument("readIV size must be 4 bytes for AES-GCM");
    if (args.nonceExplicit.size() != 8)
        throw std::invalid_argument("nonceExplicit size must be 8 bytes for AES-GCM");
    if (args.encryptedData.size() < 16)
        throw std::invalid_argument("Encrypted data too short; missing authentication tag");

    // Separate the ciphertext and the authentication tag
    const size_t tag_len = 16;
    size_t ciphertext_len = args.encryptedData.size() - tag_len;
    std::vector<uint8_t> ciphertext(args.encryptedData.begin(), args.encryptedData.begin() + ciphertext_len);
    std::vector<uint8_t> tag(args.encryptedData.begin() + ciphertext_len, args.encryptedData.end());

    // Construct the 12-byte nonce: implicit (readIV, 4 bytes) || explicit (nonceExplicit, 8 bytes)
    std::vector<uint8_t> nonce(16);
    std::copy(args.readIV.begin(), args.readIV.end(), nonce.begin());
    std::copy(args.nonceExplicit.begin(), args.nonceExplicit.end(), nonce.begin() + 4);
    // again, some1 said that 000001 is appended to the nonce to make it 128bit
    int idx = 12;
    nonce[idx++] = 0;
    nonce[idx++] = 0;
    nonce[idx++] = 0;
    nonce[idx++] = 1;

    unique_ptr_with_fnptr_deleter<EVP_CIPHER_CTX> ctx(
        EVP_CIPHER_CTX_new(),
        [](EVP_CIPHER_CTX *ptr) { if (ptr) EVP_CIPHER_CTX_free(ptr); }
    );
    if (!ctx)
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    // Initialise decryption context with AES-128-GCM
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    // Set IV length to 12 bytes
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");

    // Provide key and IV (nonce)
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, args.key.data(), nonce.data()) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex (key/IV) failed");

    int outlen = 0;
    // Process any additional authenticated data (AAD)
    if (!args.additionalData.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen,
                              args.additionalData.data(), args.additionalData.size()) != 1)
            throw std::runtime_error("EVP_DecryptUpdate (AAD) failed");
    }

    // Decrypt the ciphertext
    std::vector<uint8_t> plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outlen,
                          ciphertext.data(), ciphertext.size()) != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");
    int plaintext_len = outlen;

    // Set the expected authentication tag for verification
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (SET_TAG) failed");

    // Finalise decryption. If the tag does not verify, this call will fail.
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outlen, &outlen) != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed: authentication tag mismatch");
    plaintext_len += outlen;
    plaintext.resize(plaintext_len);
    return plaintext;
}
