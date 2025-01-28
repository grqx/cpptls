#ifndef TLS_CLIENT_CRYPTO_SHA256_H
#define TLS_CLIENT_CRYPTO_SHA256_H

#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>

class SHA256 {
public:
    SHA256() {
        reset();
    }

    void update(const std::string& data) {
        if (finalized) {
            throw std::logic_error("Cannot update after finalisation");
        }
        for (unsigned char c : data) {
            addByte(c);
        }
    }

    std::string hexdigest() {
        finalize();
        std::ostringstream result;
        for (uint8_t byte : cachedDigest) {
            result << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return result.str();
    }

    std::vector<uint8_t> digest() {
        finalize();
        return {cachedDigest.begin(), cachedDigest.end()};
    }

    void reset() {
        buffer.clear();
        totalBits = 0;
        hashValues = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        finalized = false;
        cachedDigest.fill(0);
    }

    static std::vector<uint8_t> calculate(const std::vector<uint8_t>& data) {
        SHA256 sha256;
        for (uint8_t byte : data) {
            sha256.addByte(byte);
        }
        return sha256.digest();
    }
private:
    static constexpr size_t BlockSize = 64; // 512 bits
    static constexpr size_t HashValuesSize = 8; // SHA256 hash is 256 bits (8 x 32-bit values)

    std::vector<uint8_t> buffer;
    uint64_t totalBits = 0;
    std::array<uint32_t, HashValuesSize> hashValues;
    std::array<uint8_t, 32> cachedDigest;
    bool finalized = false;

    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    void addByte(uint8_t byte) {
        buffer.push_back(byte);
        if (buffer.size() == BlockSize) {
            processBlock(buffer);
            buffer.clear();
        }
        totalBits += 8;
    }

    void finalize() {
        if (finalized) {
            return; // Do nothing if already finalised
        }

        buffer.push_back(0x80); // Padding: 1 bit followed by 0 bits
        while (buffer.size() != 56) {
            if (buffer.size() > 56) {
                buffer.resize(BlockSize, 0);
                processBlock(buffer);
                buffer.clear();
            } else {
                buffer.push_back(0);
            }
        }

        // Append totalBits (big-endian)
        for (int i = 7; i >= 0; --i) {
            buffer.push_back(static_cast<uint8_t>((totalBits >> (i * 8)) & 0xFF));
        }
        processBlock(buffer);
        buffer.clear();

        // Cache the digest
        size_t idx = 0;
        for (uint32_t val : hashValues) {
            for (int i = 3; i >= 0; --i) {
                cachedDigest[idx++] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
            }
        }
        finalized = true;
    }

    void processBlock(const std::vector<uint8_t>& block) {
        std::array<uint32_t, 64> W = {};
        for (size_t i = 0; i < 16; ++i) {
            W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }
        for (size_t i = 16; i < 64; ++i) {
            W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
        }

        auto a = hashValues[0];
        auto b = hashValues[1];
        auto c = hashValues[2];
        auto d = hashValues[3];
        auto e = hashValues[4];
        auto f = hashValues[5];
        auto g = hashValues[6];
        auto h = hashValues[7];

        for (size_t i = 0; i < 64; ++i) {
            uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
            uint32_t T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        hashValues[0] += a;
        hashValues[1] += b;
        hashValues[2] += c;
        hashValues[3] += d;
        hashValues[4] += e;
        hashValues[5] += f;
        hashValues[6] += g;
        hashValues[7] += h;
    }

    static uint32_t rotateRight(uint32_t value, uint32_t count) {
        return (value >> count) | (value << (32 - count));
    }

    static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static uint32_t Sigma0(uint32_t x) {
        return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
    }

    static uint32_t Sigma1(uint32_t x) {
        return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
    }

    static uint32_t sigma0(uint32_t x) {
        return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
    }

    static uint32_t sigma1(uint32_t x) {
        return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
    }
};

#endif
