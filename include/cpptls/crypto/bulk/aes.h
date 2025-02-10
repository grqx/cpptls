#ifndef LIBCPPTLS_CRYPTO_BULK_AES_H
#define LIBCPPTLS_CRYPTO_BULK_AES_H

#include <cpptls/crypto/bulk.h>
#include <cpptls/export.h>

#include <cstdint>
#include <vector>

TLS_CLIENT_API
std::vector<uint8_t> encryptAES_128_CBC(BlockOrStreamEncFnArgsType);
TLS_CLIENT_API
std::vector<uint8_t> decryptAES_128_CBC(BlockOrStreamDecFnArgsType);

TLS_CLIENT_API
std::vector<uint8_t> encryptAES_256_CBC(BlockOrStreamEncFnArgsType);
TLS_CLIENT_API
std::vector<uint8_t> decryptAES_256_CBC(BlockOrStreamDecFnArgsType);

TLS_CLIENT_API
std::vector<uint8_t> encryptAES_128_GCM(AEADEncFnArgsType);
TLS_CLIENT_API
std::vector<uint8_t> decryptAES_128_GCM(AEADDecFnArgsType);

#endif