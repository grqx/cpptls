#include <TLS_client/crypto/hash/sha256.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace {
uint32_t rotateRight(uint32_t value, uint32_t count)
{
    return (value >> count) | (value << (32 - count));
}

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t Sigma0(uint32_t x)
{
    return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
}

uint32_t Sigma1(uint32_t x)
{
    return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
}

uint32_t sigma0(uint32_t x)
{
    return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
}

uint32_t sigma1(uint32_t x)
{
    return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
}
};  // namespace

SHA256::SHA256()
{
    reset();
}

void SHA256::reset()
{
    buffer.clear();
    totalBits = 0;
    hashValues = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    finalized = false;
    cachedDigest.fill(0);
}

std::string SHA256::hexdigest()
{
    finalize();
    std::ostringstream result;
    for (uint8_t byte : cachedDigest) {
        result << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return result.str();
}

std::vector<uint8_t> SHA256::digest()
{
    finalize();
    return {cachedDigest.begin(), cachedDigest.end()};
}

void SHA256::update(std::string_view data)
{
    if (finalized) throw std::logic_error("Cannot update after finalisation");
    for (auto &&c : data) addByte(c);
}

void SHA256::update(const std::vector<uint8_t> &data)
{
    if (finalized) throw std::logic_error("Cannot update after finalisation");
    for (auto &&c : data) addByte(c);
}

// static method
std::vector<uint8_t> SHA256::calculate(const std::vector<uint8_t> &data)
{
    SHA256 sha256;
    for (auto &&byte : data) sha256.addByte(byte);
    return sha256.digest();
}

void SHA256::addByte(uint8_t byte)
{
    buffer.push_back(byte);
    if (buffer.size() == BlockSize) {
        processBlock(buffer);
        buffer.clear();
    }
    totalBits += 8;
}

void SHA256::finalize()
{
    if (finalized) {
        return;  // Do nothing if already finalised
    }

    buffer.push_back(0x80);  // Padding: 1 bit followed by 0 bits
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

void SHA256::processBlock(const std::vector<uint8_t> &block)
{
    std::array<uint32_t, 64> W = {};
    for (size_t i = 0; i < 16; ++i) {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) |
               block[i * 4 + 3];
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
