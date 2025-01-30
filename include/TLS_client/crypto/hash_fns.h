#ifndef TLS_CLIENT_CRYPTO_HASH_FNS_H
#define TLS_CLIENT_CRYPTO_HASH_FNS_H

#include <array>
#include <cstdint>
#include <cstring>  // for std::memcpy
#include <vector>

namespace ChatGPT4o {
inline std::vector<uint8_t> TLS_sha1(const std::vector<uint8_t> &data)
{
    // Constants for SHA-1
    constexpr std::array<uint32_t, 5> h0 = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                                            0xC3D2E1F0};

    // Pre-processing
    size_t original_size = data.size();
    size_t bit_length = original_size * 8;

    // Calculate padding
    size_t padded_size = ((original_size + 8) / 64 + 1) * 64;
    std::vector<uint8_t> padded_data(padded_size, 0);

    // Copy original data
    std::memcpy(padded_data.data(), data.data(), original_size);

    // Append the bit '1' (0x80 in binary form)
    padded_data[original_size] = 0x80;

    // Append the original message length as a 64-bit big-endian integer
    for (size_t i = 0; i < 8; ++i) {
        padded_data[padded_size - 1 - i] = static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF);
    }

    // SHA-1 state variables
    std::array<uint32_t, 5> h = h0;

    // Process the message in successive 512-bit chunks
    for (size_t chunk_start = 0; chunk_start < padded_size; chunk_start += 64) {
        uint32_t w[80] = {0};

        // Break chunk into sixteen 32-bit big-endian words
        for (size_t i = 0; i < 16; ++i) {
            w[i] = (padded_data[chunk_start + i * 4] << 24) |
                   (padded_data[chunk_start + i * 4 + 1] << 16) |
                   (padded_data[chunk_start + i * 4 + 2] << 8) |
                   (padded_data[chunk_start + i * 4 + 3]);
        }

        // Extend the first 16 words into the remaining 64 words
        for (size_t i = 16; i < 80; ++i) {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]);
            w[i] = (w[i] << 1) | (w[i] >> 31);  // Left rotate w[i] by 1
        }

        // Initialise hash value for this chunk
        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];

        // Main loop
        for (size_t i = 0; i < 80; ++i) {
            uint32_t f, k;

            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }

        // Add this chunk's hash to result
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }

    // Convert hash to bytes
    std::vector<uint8_t> hash;
    for (uint32_t value : h) {
        hash.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        hash.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        hash.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        hash.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    return hash;
}
};  // namespace ChatGPT4o

#endif
