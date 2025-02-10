#include <cpptls/crypto/hash/sha512.h>
#include <cpptls/crypto/hash/sha_macros.h>

#include <cstring>
#include <iomanip>
#include <sstream>

#define SIGMA0(x) MAKE_S(x, 28, 34, 39)
#define SIGMA1(x) MAKE_S(x, 14, 18, 41)
#define sigma0(x) MAKE_s(x, 1, 8, 7)
#define sigma1(x) MAKE_s(x, 19, 61, 6)

HashAlgo_SHA512::HashAlgo_SHA512()
{
    reset();
}

void HashAlgo_SHA512::reset()
{
    buffer.clear();
    totalBits = 0;
    finalized = false;
    hashValues = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
                  0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
}

void HashAlgo_SHA512::update(std::string_view data)
{
    update(std::vector<uint8_t>(data.begin(), data.end()));
}

void HashAlgo_SHA512::update(const std::vector<uint8_t>& data)
{
    buffer.insert(buffer.end(), data.begin(), data.end());
    totalBits += data.size() * 8;

    while (buffer.size() >= BlockSize) {
        std::vector<uint8_t> block(buffer.begin(), buffer.begin() + BlockSize);
        processBlock(block);
        buffer.erase(buffer.begin(), buffer.begin() + BlockSize);
    }
}

void HashAlgo_SHA512::finalize()
{
    if (finalized) return;
    finalized = true;

    uint64_t bitLength = totalBits;
    buffer.push_back(0x80);
    while ((buffer.size() + 16) % BlockSize != 0) {
        buffer.push_back(0x00);
    }

    std::vector<uint8_t> lengthBytes(16, 0);
    for (int i = 0; i < 8; ++i) {
        lengthBytes[15 - i] = static_cast<uint8_t>(bitLength >> (i * 8));
    }
    buffer.insert(buffer.end(), lengthBytes.begin(), lengthBytes.end());

    while (!buffer.empty()) {
        std::vector<uint8_t> block(buffer.begin(), buffer.begin() + BlockSize);
        processBlock(block);
        buffer.erase(buffer.begin(), buffer.begin() + BlockSize);
    }
}

std::vector<uint8_t> HashAlgo_SHA512::digest()
{
    if (!finalized) finalize();
    std::vector<uint8_t> output(64);
    for (size_t i = 0; i < 8; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            output[i * 8 + j] = static_cast<uint8_t>(hashValues[i] >> (56 - j * 8));
        }
    }
    return output;
}

std::string HashAlgo_SHA512::hexdigest()
{
    std::ostringstream oss;
    for (uint8_t byte : digest()) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<uint8_t> HashAlgo_SHA512::calculate(const std::vector<uint8_t>& data)
{
    HashAlgo_SHA512 sha;
    sha.update(data);
    return sha.digest();
}

void HashAlgo_SHA512::processBlock(const std::vector<uint8_t>& block)
{
    std::array<uint64_t, 80> w;
    for (size_t i = 0; i < 16; ++i) {
        w[i] = 0;
        for (size_t j = 0; j < 8; ++j) {
            w[i] |= static_cast<uint64_t>(block[i * 8 + j]) << (56 - j * 8);
        }
    }
    for (size_t i = 16; i < 80; ++i) {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }

    std::array<uint64_t, 8> state = hashValues;
    for (size_t i = 0; i < 80; ++i) {
        uint64_t t1 = state[7] + SIGMA1(state[4]) + CH(state[4], state[5], state[6]) + K[i] + w[i];
        uint64_t t2 = SIGMA0(state[0]) + MAJ(state[0], state[1], state[2]);
        state[7] = state[6];
        state[6] = state[5];
        state[5] = state[4];
        state[4] = state[3] + t1;
        state[3] = state[2];
        state[2] = state[1];
        state[1] = state[0];
        state[0] = t1 + t2;
    }

    for (size_t i = 0; i < 8; ++i) {
        hashValues[i] += state[i];
    }
}

std::vector<uint8_t> HashAlgo_SHA384::calculate(const std::vector<uint8_t>& data)
{
    HashAlgo_SHA512 sha512;
    sha512.update(data);
    auto fullDigest = sha512.digest();
    return std::vector<uint8_t>(fullDigest.begin(), fullDigest.begin() + 48);
}
