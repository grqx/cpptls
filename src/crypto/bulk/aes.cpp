
#include <cpptls/crypto/bulk/aes.h>
#include <cpptls/tls_memory.h>

#include <algorithm>
#include <cassert>
#include <stdexcept>
#include <type_traits>
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
template <bool IS_ENCRYPT_MODE, size_t KEY_SIZE, size_t IV_SIZE, typename LCI, size_t TAG_SIZE = 0UL>
std::optional<std::vector<uint8_t>> linuxCryptoAPI_crypt(
        const uint8_t *key, const uint8_t *iv, const std::vector<uint8_t> &data,
        uint32_t aadLen = 0, const uint8_t *aad = nullptr)
{
    int alg_s = -1, aes_fd = -1;
    int pipes[2] = {-1, -1};
    try {
        alg_s = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (alg_s < 0) throw std::runtime_error("Failed to create AF_ALG socket");

        auto *psa = reinterpret_cast<const sockaddr *>(&LCI::sa);
        if (bind(alg_s, const_cast<sockaddr *>(psa), sizeof(struct sockaddr_alg)) == -1)
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

// TODO: generic std::optional<std::vector<uint8_t>> openSSLAPI_crypt
typedef const EVP_CIPHER *(CipherGetterFn)();

#define AES_IMPL_HAS_OSSL
#ifndef AES_HAS_IMPL
#define AES_HAS_IMPL
#endif  // AES_HAS_IMPL
#endif  // AES_IMPL_HAS_OSSL

#ifndef AES_HAS_IMPL
#error "No available AES implementation"
#endif

namespace {

template <size_t KEY_SIZE, size_t FIV_SIZE, typename CI, size_t TAG_SIZE = 0, size_t NONCE_SIZE = 0>
std::vector<uint8_t> encryptAES(
    std::conditional_t<CI::isAEAD, AEADEncFnArgsType, BlockOrStreamEncFnArgsType> args)
{
    if (args.data.empty()) return {};
    if (args.key.size() != KEY_SIZE)
        throw std::invalid_argument("key size mismatch");
    if (args.iv.size() != FIV_SIZE)
        throw std::invalid_argument("iv size mismatch");

    uint8_t maybe_nonce[FIV_SIZE + NONCE_SIZE];
    const uint8_t *encIV = args.iv.data();
    size_t aadLen = 0;
    const uint8_t *aad = nullptr;

    if constexpr (CI::isAEAD) {
        if (args.nonceExplicit.size() != NONCE_SIZE)
            throw std::invalid_argument("nonceExplicit size mismatch");
        std::copy(args.iv.begin(), args.iv.end(), maybe_nonce);
        std::copy(args.nonceExplicit.begin(), args.nonceExplicit.end(), maybe_nonce + FIV_SIZE);
        encIV = +maybe_nonce;
        aadLen = args.additionalData.size();
        aad = args.additionalData.data();
    }

#ifdef AES_IMPL_HAS_LINUX
    if (auto caRes = linuxCryptoAPI_crypt<true, KEY_SIZE, FIV_SIZE + NONCE_SIZE, CI, TAG_SIZE>(
                args.key.data(), encIV, args.data, aadLen, aad))
        return *caRes;
    throw std::runtime_error("linux crypto api failed");
#elif AES_IMPL_HAS_OSSL
    unique_ptr_with_fnptr_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (1 != EVP_EncryptInit_ex(ctx.get(), CI::template CipherGetter<KEY_SIZE>(), nullptr, args.key.data(), encIV))
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    int outlen = 0;
    if constexpr (CI::isAEAD)
        if (aadLen)
            if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, aad,
                                  aadLen) != 1)
                throw std::runtime_error("EVP_EncryptUpdate failed (AEAD AAD)");

    std::vector<uint8_t> ciphertext(args.data.size() + TAG_SIZE);
    int ciphertext_len;
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &ciphertext_len, args.data.data(),
                          args.data.size()) != 1)
        throw std::runtime_error("EVP_EncryptUpdate failed");

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outlen, &outlen) != 1)
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    ciphertext_len += outlen;

    if constexpr (CI::isAEAD)
        if (TAG_SIZE)
            if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, ciphertext.data() + args.data.size()) != 1)
                throw std::runtime_error("EVP_CIPHER_CTX_ctrl (GET_TAG) failed");

    return ciphertext;
#else
    UNREACHABLE
#endif
}

template <size_t KEY_SIZE, size_t FIV_SIZE, typename CI, size_t TAG_SIZE = 0, size_t NONCE_SIZE = 0>
std::vector<uint8_t> decryptAES(
    std::conditional_t<CI::isAEAD, AEADDecFnArgsType, BlockOrStreamDecFnArgsType> args)
{
    if (args.encryptedData.empty()) return {};
    if (args.key.size() != KEY_SIZE) throw std::invalid_argument("key size mismatch");
    if (args.iv.size() != FIV_SIZE)
        throw std::invalid_argument("iv size mismatch");

    uint8_t maybe_nonce[FIV_SIZE + NONCE_SIZE];
    const uint8_t *encIV = args.iv.data();
    size_t aadLen = 0;
    const uint8_t *aad = nullptr;

    if constexpr (CI::isAEAD) {
        if (args.nonceExplicit.size() != NONCE_SIZE)
            throw std::invalid_argument("nonceExplicit size mismatch");
        if (args.encryptedData.size() < TAG_SIZE)
            throw std::invalid_argument("Encrypted data too short; missing authentication tag");
        std::copy(args.iv.begin(), args.iv.end(), maybe_nonce);
        std::copy(args.nonceExplicit.begin(), args.nonceExplicit.end(), maybe_nonce + FIV_SIZE);
        encIV = +maybe_nonce;
        aadLen = args.additionalData.size();
        aad = args.additionalData.data();
    }

#ifdef AES_IMPL_HAS_LINUX
    if (auto caRes = linuxCryptoAPI_crypt<false, KEY_SIZE, FIV_SIZE + NONCE_SIZE, CI, TAG_SIZE>(
            args.key.data(), encIV, args.encryptedData, aadLen, aad))
        return *caRes;
    throw std::runtime_error("afalg failed");
#elif AES_IMPL_HAS_OSSL
    size_t ciphertext_len = args.encryptedData.size() - TAG_SIZE;
    unique_ptr_with_fnptr_deleter<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (EVP_DecryptInit_ex(ctx.get(), CI::template CipherGetter<KEY_SIZE>(), nullptr, args.key.data(), encIV) != 1)
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    int outlen = 0;
    if constexpr (CI::isAEAD)
        if (aadLen)
            if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen, aad, aadLen) != 1)
                throw std::runtime_error("EVP_DecryptUpdate (AAD) failed");

    std::vector<uint8_t> plaintext(ciphertext_len);
    int plaintext_len;
    if (1 != EVP_DecryptUpdate(
            ctx.get(), plaintext.data(), &plaintext_len,
            args.encryptedData.data(), ciphertext_len))
        throw std::runtime_error("EVP_DecryptUpdate failed");

    if constexpr (CI::isAEAD)
        if (1 != EVP_CIPHER_CTX_ctrl(
                ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                const_cast<uint8_t *>(args.encryptedData.data() + ciphertext_len)))
            throw std::runtime_error("EVP_CIPHER_CTX_ctrl (SET_TAG) failed");

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + plaintext_len, &outlen) != 1)
        throw std::runtime_error("EVP_DecryptFinal_ex failed: authentication tag mismatch");
    plaintext_len += outlen;
    plaintext.resize(plaintext_len);
    return plaintext;
#else
    UNREACHABLE
#endif
}

struct AES_CBC_CI {
    constexpr static bool isAEAD = false;
#ifdef AES_IMPL_HAS_LINUX
    constexpr static struct sockaddr_alg sa {
        AF_ALG, "skcipher",
        0, 0, "cbc(aes)",
    };
#endif
#ifdef AES_IMPL_HAS_OSSL
template <size_t KEY_SIZE, typename = std::enable_if_t<KEY_SIZE == 16 || KEY_SIZE == 32>>
constexpr static CipherGetterFn *CipherGetter = (
    KEY_SIZE == 16 ? &EVP_aes_128_cbc : &EVP_aes_256_cbc);
#endif
};
struct AES_GCM_CI {
    constexpr static bool isAEAD = true;
#ifdef AES_IMPL_HAS_LINUX
    constexpr static struct sockaddr_alg sa {
        AF_ALG, "aead",
        0, 0, "gcm(aes)",
    };
#endif
#ifdef AES_IMPL_HAS_OSSL
template <size_t KEY_SIZE, typename = std::enable_if_t<KEY_SIZE == 16 || KEY_SIZE == 32>>
constexpr static CipherGetterFn *CipherGetter = (
    KEY_SIZE == 16 ? &EVP_aes_128_gcm : &EVP_aes_256_gcm);
#endif
};
}  // namespace

std::vector<uint8_t> encryptAES_128_CBC(BlockOrStreamEncFnArgsType args) {
    return encryptAES<16, 16, AES_CBC_CI>(args);
}
std::vector<uint8_t> decryptAES_128_CBC(BlockOrStreamDecFnArgsType args) {
    return decryptAES<16, 16, AES_CBC_CI>(args);
}
std::vector<uint8_t> encryptAES_256_CBC(BlockOrStreamEncFnArgsType args) {
    return encryptAES<32, 16, AES_CBC_CI>(args);
}
std::vector<uint8_t> decryptAES_256_CBC(BlockOrStreamDecFnArgsType args) {
    return decryptAES<32, 16, AES_CBC_CI>(args);
}

std::vector<uint8_t> encryptAES_128_GCM(AEADEncFnArgsType args) {
    return encryptAES<16, 4, AES_GCM_CI, 16, 8>(args);
}
std::vector<uint8_t> decryptAES_128_GCM(AEADDecFnArgsType args) {
    return decryptAES<16, 4, AES_GCM_CI, 16, 8>(args);
}
std::vector<uint8_t> encryptAES_256_GCM(AEADEncFnArgsType args) {
    return encryptAES<32, 4, AES_GCM_CI, 16, 8>(args);
}
std::vector<uint8_t> decryptAES_256_GCM(AEADDecFnArgsType args) {
    return decryptAES<32, 4, AES_GCM_CI, 16, 8>(args);
}
