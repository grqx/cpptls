#ifndef TLS_CLIENT_CRYPTO_BULK_AES_H
#define TLS_CLIENT_CRYPTO_BULK_AES_H

#include <TLS_client/crypto/bulk.h>

#include <cstdint>
#include <vector>

std::vector<uint8_t> encryptAES_128_CBC(symEncFnArgsType args);
std::vector<uint8_t> decryptAES_128_CBC(symDecFnArgsType args);

#endif