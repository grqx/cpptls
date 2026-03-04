
#include <cpptls/crypto/bulk/aes.h>
#include <cpptls/tls_memory.h>

#include <algorithm>
#include <cassert>
#include <stdexcept>
// TODO: port AES 256 GCM
// ossl afalg impl:
// https://github.com/openssl/openssl/blob/4b4333ffcc8e4ecbf5c70214769c77c7a1bb684f/engines/e_afalg.c#L440C57-L440C67
#ifndef AES_IMPL_HAS_LINUX
#pragma region GNU_LINUX_CRYPTO_AES_IMPL
#ifdef __linux__
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
#define _GNU_SOURCE 1
#include <fcntl.h>
#include <linux/if_alg.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef AF_ALG
#include <cstddef>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <sys/uio.h>
using namespace std::string_literals;

namespace {
using AlgoTypeNameType = const char *;
using AlgoNameType = const char *;
constexpr AlgoTypeNameType symmetricAlgoType = "skcipher";
constexpr AlgoTypeNameType AEADAlgoType = "aead";
constexpr AlgoNameType AES_CBCAlgoName = "cbc(aes)";
constexpr AlgoNameType AES_GCMAlgoName = "gcm(aes)";
template <bool IS_ENCRYPT_MODE, size_t KEY_SIZE, size_t IV_SIZE, size_t TAG_SIZE = 0UL>
std::optional<std::vector<uint8_t>> linuxCryptoAPI_crypt(const uint8_t *key, const uint8_t *iv,
                                                         const std::vector<uint8_t> &data,
                                                         AlgoTypeNameType algoType,
                                                         AlgoNameType algoName, uint32_t aadLen = 0,
                                                         const uint8_t *aad = nullptr)
{
    int alg_s = -1, aes_fd = -1;
    int pipes[2] = {-1, -1};
    try {
        alg_s = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (alg_s < 0) throw std::runtime_error("Failed to create AF_ALG socket");

        struct sockaddr_alg sa {
            AF_ALG
        };
        std::memcpy(sa.salg_type, algoType, strlen(algoType));
        std::memcpy(sa.salg_name, algoName, strlen(algoName));

        if (bind(alg_s, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)) == -1)
            throw std::runtime_error("Bind failed");

        if (setsockopt(alg_s, SOL_ALG, ALG_SET_KEY, key, KEY_SIZE) == -1)
            throw std::runtime_error("Failed to set key");

        if constexpr (TAG_SIZE) {
            if (setsockopt(alg_s, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, TAG_SIZE) == -1)
                throw std::runtime_error("Failed to set AEAD Auth size");
        }

        aes_fd = accept(alg_s, nullptr, nullptr);
        close(alg_s);
        alg_s = -1;

        if (aes_fd == -1) throw std::runtime_error("Accept failed");

        uint8_t cmsg_buf[CMSG_SPACE(sizeof(uint32_t)) +
                         CMSG_SPACE(sizeof(struct af_alg_iv) + IV_SIZE) +
                         (TAG_SIZE ? CMSG_SPACE(sizeof(uint32_t)) : 0)] = {0};
        struct msghdr msg {
        };
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_OP;
        *reinterpret_cast<uint32_t *>(CMSG_DATA(cmsg)) =
            IS_ENCRYPT_MODE ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

        cmsg = CMSG_NXTHDR(&msg, cmsg);
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + IV_SIZE);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_IV;
        auto *iv_data = reinterpret_cast<struct af_alg_iv *>(CMSG_DATA(cmsg));
        iv_data->ivlen = IV_SIZE;
        std::memcpy(iv_data->iv, iv, IV_SIZE);

        if constexpr (TAG_SIZE) {
            cmsg = CMSG_NXTHDR(&msg, cmsg);
            cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
            cmsg->cmsg_level = SOL_ALG;
            cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
            *reinterpret_cast<uint32_t *>(CMSG_DATA(cmsg)) = aadLen;
        }

        if (sendmsg(aes_fd, &msg, 0) == -1) throw std::runtime_error("sendmsg failed");

        if (pipe(pipes) == -1) throw std::runtime_error("Pipe creation failed");

        if (TAG_SIZE && aad && aadLen) {
            /* The user space caller must arrange the aforementioned information in the following
             * order:
             *
             * AEAD encryption input: AAD || plaintext
             * AEAD decryption input: AAD || ciphertext || authentication tag
             * The output buffer the user space caller provides must be at least as large to hold
             * the following data:
             *
             * AEAD encryption output: ciphertext || authentication tag
             * AEAD decryption output: plaintext
             */
            struct iovec iov_aad = {const_cast<uint8_t *>(aad), aadLen};
            if (vmsplice(pipes[1], &iov_aad, 1, SPLICE_F_GIFT) == -1)
                throw std::runtime_error("vmsplice failed");

            if (splice(pipes[0], nullptr, aes_fd, nullptr, aadLen, SPLICE_F_MORE) == -1)
                throw std::runtime_error("splice failed");
        }
        struct iovec iov = {const_cast<uint8_t *>(data.data()), data.size()};
        std::vector<uint8_t> output(IS_ENCRYPT_MODE ? data.size() + TAG_SIZE
                                                    : data.size() - TAG_SIZE);
        if (vmsplice(pipes[1], &iov, 1, SPLICE_F_GIFT) == -1)
            throw std::runtime_error("vmsplice failed");

        if (splice(pipes[0], nullptr, aes_fd, nullptr, data.size(), 0) == -1)
            throw std::runtime_error("splice failed");
        std::vector<uint8_t> unused_aad(aadLen);
        struct iovec iov_read[2] = {
            {unused_aad.data(), unused_aad.size()},
            {output.data(), output.size()},
        };
        auto readBytes = readv(aes_fd, iov_read, 2);
        if (readBytes == unused_aad.size() + output.size()) {
            close(pipes[0]);
            pipes[0] = -1;
            close(pipes[1]);
            pipes[1] = -1;
            close(aes_fd);
            aes_fd = -1;
            return output;
        }
        if (readBytes < 0)
            throw std::runtime_error((IS_ENCRYPT_MODE ? "Encryption"s : "Decryption"s) +
                                     " failed"s);
        else if (readBytes == 0)
            throw std::runtime_error((IS_ENCRYPT_MODE ? "Encryption"s : "Decryption"s) +
                                     " terminated"s);
        else if (readBytes > 0 && readBytes < output.size())
            throw std::runtime_error("Unexpected "s +
                                     (IS_ENCRYPT_MODE ? "encryption"s : "decryption"s) +
                                     " result(expceted more), size: "s + std::to_string(readBytes));
        else
            throw std::runtime_error("Unexpected "s +
                                     (IS_ENCRYPT_MODE ? "encryption"s : "decryption"s) +
                                     " result(expected less), size: "s + std::to_string(readBytes));
    } catch (std::exception &e) {
        for (auto &&i : {alg_s, aes_fd, pipes[0], pipes[1]})
            if (i >= 0) close(i);
        std::cerr << "caught exception in " << __func__ << ", what(): " << e.what()
                  << ", errno: " << errno << '\n';
        return std::nullopt;
    }
}
}  // namespace
#define AES_IMPL_HAS_LINUX
#ifndef AES_HAS_IMPL
#define AES_HAS_IMPL
#endif
#endif  // AF_ALG
#endif  // linux version
#endif  // linux
#pragma endregion GNU_LINUX_CRYPTO_AES_IMPL
#endif  // AES_IMPL_HAS_LINUX

#ifndef AES_IMPL_HAS_OSSL
#include <openssl/evp.h>

typedef const EVP_CIPHER *(CipherGetterFn)();

template <size_t KEY_SIZE, typename = std::enable_if_t<KEY_SIZE == 16 || KEY_SIZE == 32>>
constexpr static CipherGetterFn *AESGCM_CipherGetterFnPtr = KEY_SIZE == 16 ? &EVP_aes_128_gcm : &EVP_aes_256_gcm;
template <size_t KEY_SIZE, typename = std::enable_if_t<KEY_SIZE == 16 || KEY_SIZE == 32>>
constexpr static CipherGetterFn *AESCBC_CipherGetterFnPtr = (
    KEY_SIZE == 16 ? &EVP_aes_128_cbc : &EVP_aes_256_cbc);

// TODO: generic std::optional<std::vector<uint8_t>> openSSLAPI_crypt
#define AES_IMPL_HAS_OSSL
#ifndef AES_HAS_IMPL
#define AES_HAS_IMPL
#endif  // AES_HAS_IMPL
#endif  // AES_IMPL_HAS_OSSL

#ifndef AES_HAS_IMPL
#error "No available AES implementation"
#endif

namespace {
template <size_t KEY_SIZE, size_t TAG_SIZE = 16>
std::vector<uint8_t> encryptAES_GCM(AEADEncFnArgsType args)
{
    if (args.data.empty()) return args.data;
    if (args.key.size() != KEY_SIZE) throw std::invalid_argument("AES-GCM Key size mismatch");
    if (args.writeIV.size() != 4)
        throw std::invalid_argument("writeIV size must be 4 bytes for AES-GCM");
    if (args.nonceExplicit.size() != 8)
        throw std::invalid_argument("nonceExplicit size must be 8 bytes for AES-GCM");

    uint8_t nonce[12];
    std::copy(args.writeIV.begin(), args.writeIV.end(), nonce);
    std::copy(args.nonceExplicit.begin(), args.nonceExplicit.end(), nonce + 4);
#ifdef AES_IMPL_HAS_LINUX
    if (auto caRes = linuxCryptoAPI_crypt<true, KEY_SIZE, 12UL, TAG_SIZE>(
            args.key.data(), nonce, args.data, AEADAlgoType, AES_GCMAlgoName,
            args.additionalData.size(), args.additionalData.data()))
        return *caRes;
    std::cerr << __func__ << ": Falling back to OpenSSL\n"s;
#endif
    unique_ptr_with_fnptr_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (EVP_EncryptInit_ex(ctx.get(), AESGCM_CipherGetterFnPtr<KEY_SIZE>(), nullptr, args.key.data(), nonce) != 1)
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if (!args.additionalData.empty()) {
        int outlen = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, args.additionalData.data(),
                              args.additionalData.size()) != 1)
        assert(outlen == args.additionalData.size());
    }

    std::vector<uint8_t> ciphertext(args.data.size() + TAG_SIZE);
    int ciphertext_len;
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &ciphertext_len, args.data.data(),
                          args.data.size()) != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");
    assert(ciphertext_len = args.data.size());

    int outlen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outlen, &outlen) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    assert(!outlen);
    ciphertext_len += outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, ciphertext.data() + ciphertext.size() - TAG_SIZE) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (GET_TAG) failed");

    return ciphertext;
}

template <size_t KEY_SIZE, size_t TAG_SIZE = 16>
std::vector<uint8_t> decryptAES_GCM(AEADDecFnArgsType args)
{
    if (args.encryptedData.empty()) return args.encryptedData;
    if (args.key.size() != KEY_SIZE) throw std::invalid_argument("AES-GCM Key size mismatch");
    if (args.readIV.size() != 4)
        throw std::invalid_argument("readIV size must be 4 bytes for AES-GCM");
    if (args.nonceExplicit.size() != 8)
        throw std::invalid_argument("nonceExplicit size must be 8 bytes for AES-GCM");
    if (args.encryptedData.size() < TAG_SIZE)
        throw std::invalid_argument("Encrypted data too short; missing authentication tag");

    // Construct the 12-byte nonce: implicit (readIV, 4 bytes) || explicit (nonceExplicit, 8 bytes)
    uint8_t nonce[12];
    std::copy(args.readIV.begin(), args.readIV.end(), nonce);
    std::copy(args.nonceExplicit.begin(), args.nonceExplicit.end(), nonce + 4);
#ifdef AES_IMPL_HAS_LINUX
    if (auto caRes = linuxCryptoAPI_crypt<false, KEY_SIZE, 12UL, TAG_SIZE>(
            args.key.data(), nonce, args.encryptedData, AEADAlgoType, AES_GCMAlgoName,
            args.additionalData.size(), args.additionalData.data()))
        return *caRes;
    std::cerr << __func__ + ": Falling back to OpenSSL\n"s;
#endif

    size_t ciphertext_len = args.encryptedData.size() - TAG_SIZE;
    std::vector<uint8_t> ciphertext(args.encryptedData.begin(),
                                    args.encryptedData.begin() + ciphertext_len);
    std::vector<uint8_t> tag(args.encryptedData.begin() + ciphertext_len, args.encryptedData.end());
    unique_ptr_with_fnptr_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (EVP_DecryptInit_ex(ctx.get(), AESGCM_CipherGetterFnPtr<KEY_SIZE>(), nullptr, args.key.data(), nonce) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    int outlen = 0;
    if (!args.additionalData.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen, args.additionalData.data(),
                              args.additionalData.size()) != 1)
            throw std::runtime_error("EVP_DecryptUpdate (AAD) failed");
    }

    std::vector<uint8_t> plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outlen, ciphertext.data(),
                          ciphertext.size()) != 1)
        throw std::runtime_error("EVP_DecryptUpdate failed");
    int plaintext_len = outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()) != 1)
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (SET_TAG) failed");

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outlen, &outlen) != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed: authentication tag mismatch");
    plaintext_len += outlen;
    plaintext.resize(plaintext_len);
    return plaintext;
}

template <size_t KEY_SIZE>
std::vector<uint8_t> encryptAES_CBC(BlockOrStreamEncFnArgsType args)
{
    if (args.data.empty()) return args.data;
    if (args.key.size() != KEY_SIZE) throw std::invalid_argument("AES-CBC key size mismatch");
    if (args.iv.size() != 16) throw std::invalid_argument("IV size must be 16 bytes for AES-CBC");
    if (args.data.size() % 16 != 0)
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES");
#ifdef AES_IMPL_HAS_LINUX
    if (auto caRes = linuxCryptoAPI_crypt<true, 16UL, 16UL>(
            args.key.data(), args.iv.data(), args.data, symmetricAlgoType, AES_CBCAlgoName))
        return *caRes;
    std::cerr << __func__ + ": Falling back to OpenSSL\n"s;
#endif
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX *ptr) {
        if (ptr) EVP_CIPHER_CTX_free(ptr);
    });
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    if (EVP_EncryptInit_ex(ctx.get(), AESCBC_CipherGetterFnPtr<KEY_SIZE>(), nullptr, args.key.data(),
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

template <size_t KEY_SIZE>
std::vector<uint8_t> decryptAES_CBC(BlockOrStreamDecFnArgsType args)
{
    if (args.encryptedData.empty()) return args.encryptedData;
    if (args.key.size() != KEY_SIZE) throw std::invalid_argument("AES-CBC key size mismatch");
    if (args.iv.size() != 16) throw std::invalid_argument("IV size must be 16 bytes for AES-CBC");
    if (args.encryptedData.size() & 15)
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES");
#ifdef AES_IMPL_HAS_LINUX
    if (auto caRes = linuxCryptoAPI_crypt<false, KEY_SIZE, 16UL>(args.key.data(), args.iv.data(),
                                                             args.encryptedData, symmetricAlgoType,
                                                             AES_CBCAlgoName))
        return *caRes;
    std::cerr << __func__ + ": Falling back to OpenSSL\n"s;
#endif
    unique_ptr_with_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    if (EVP_DecryptInit_ex(ctx.get(), AESCBC_CipherGetterFnPtr<KEY_SIZE>(), nullptr, args.key.data(),
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

}  // namespace

std::vector<uint8_t> encryptAES_128_CBC(BlockOrStreamEncFnArgsType args) {
    return encryptAES_CBC<16>(args);
}
std::vector<uint8_t> decryptAES_128_CBC(BlockOrStreamDecFnArgsType args) {
    return decryptAES_CBC<16>(args);
}
std::vector<uint8_t> encryptAES_256_CBC(BlockOrStreamEncFnArgsType args) {
    return encryptAES_CBC<32>(args);
}
std::vector<uint8_t> decryptAES_256_CBC(BlockOrStreamDecFnArgsType args) {
    return decryptAES_CBC<32>(args);
}

std::vector<uint8_t> encryptAES_128_GCM(AEADEncFnArgsType args) {
    return encryptAES_GCM<16>(args);
}
std::vector<uint8_t> decryptAES_128_GCM(AEADDecFnArgsType args) {
    return decryptAES_GCM<16>(args);
}
std::vector<uint8_t> encryptAES_256_GCM(AEADEncFnArgsType args) {
    return encryptAES_GCM<32>(args);
}
std::vector<uint8_t> decryptAES_256_GCM(AEADDecFnArgsType args) {
    return decryptAES_GCM<32>(args);
}
