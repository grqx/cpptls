#ifndef TLS_CLIENT_CRYPTO_HMAC_H
#define TLS_CLIENT_CRYPTO_HMAC_H

#include <TLS_client/tls_types.h>
#include <vector>
#include <cstdint>
#include <cstddef>

std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message, const HashFnType& hash_, size_t block_size);

#endif
