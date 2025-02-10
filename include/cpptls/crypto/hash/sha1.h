#ifndef LIBCPPTLS_CRYPTO_HASH_SHA1_H
#define LIBCPPTLS_CRYPTO_HASH_SHA1_H

#include <cpptls/export.h>
#include <cpptls/crypto/hash.h>

#include <cstddef>
#include <cstdint>
#include <vector>

LIBCPPTLS_API
std::vector<uint8_t> SHA1_calculate(const std::vector<uint8_t> &data);
constexpr static HashInfo SHA1_hi{SHA1_calculate, 64};

#endif
