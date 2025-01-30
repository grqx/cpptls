#ifndef TLS_CLIENT_DEBUG_H
#define TLS_CLIENT_DEBUG_H

#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "macros.h"

namespace Debugging {
template <typename CONTAINER_T>
inline const std::vector<uint8_t> forceU8ViseArr(const CONTAINER_T &t)
{
    return {std::data(t), std::data(t) + std::size(t)};
}
template <typename T>
inline const std::vector<uint8_t> forceU8Vise(const T &t)
{
    auto p = reinterpret_cast<const uint8_t *>(&t);
    return {p, p + sizeof(t)};
}

template <typename U8CONTAINER_>
inline void pu8Vec(const U8CONTAINER_ &u8vec, size_t alignTo = 8, bool addLSep = true,
                   const std::string &prefix = "", std::ostream &dest = std::cout)
{
    size_t bcnt = 0;
    if (!prefix.empty()) dest << prefix << ": ";
    for (auto &&cont_byte : u8vec) {
        char b[3] = {0, 0, 0};
        sprintf(b, "%02x", cont_byte);
        dest << b;
        if (alignTo >= 1 && ++bcnt % alignTo == 0) dest << ' ';
    }
    if (addLSep) dest << '\n';
}

extern "C" {
DEPRECATION_START
DISABLE_DEPRECATION_WARNING_START
size_t hexToBytes(const char *hex, unsigned char *buffer, size_t bufferSize)
{
    size_t byteCount = 0;

    for (size_t i = 0; hex[i] != '\0'; ++i) {
        if (hex[i] == ' ') {
            continue;
        }
        if (!isxdigit(hex[i]) || !isxdigit(hex[i + 1])) {
            fprintf(stderr, "Invalid hex character: %c%c\n", hex[i], hex[i + 1]);
            exit(1);
        }
        if (byteCount >= bufferSize) {
            fprintf(stderr, "Buffer overflow\n");
            exit(1);
        }
        unsigned int value;
        sscanf(&hex[i], "%2x", &value);
        buffer[byteCount++] = (unsigned char)value;
        ++i;  // Skip the second hex digit
    }

    return byteCount;
}
DISABLE_DEPRECATION_WARNING_END
DEPRECATION_END
}  // extern "C"

void a()
{
    hexToBytes(nullptr, nullptr, 0);
}

uint8_t parseHexDigits_(char c)
{
    if (std::isdigit(c))
        return c - '0';
    else if (std::islower(c))
        return c - 'a' + 10;
    else if (std::isupper(c))
        return c - 'A' + 10;
    else
        return UINT8_MAX;
}

std::vector<uint8_t> parseBytesArray(const std::string &str)
{
    std::vector<uint8_t> ret;
    for (size_t i = 0; i < str.size(); i += 2) {
        char d1 = str.at(i);
        if (d1 == ' ' || d1 == '\n' || d1 == '\r') continue;
        if (i + 1 >= str.size()) {
            std::cerr << "Redundant character '" << d1 << "' at the end of the string!\n";
            break;
        }
        char d2 = str.at(i + 1);
        if (d2 == ' ' || d2 == '\n' || d2 == '\r') {
            i++;
            if (i + 1 >= str.size()) {
                std::cerr << "Redundant character '" << d2 << "' at the end of the string!\n";
                break;
            }
            d2 = str.at(i + 1);
        }

        if (!std::isxdigit(d1)) {
            std::cerr << '\'' << d1 << "' is not a hex digit";
            break;
        }
        if (!std::isxdigit(d2)) {
            std::cerr << '\'' << d2 << "' is not a hex digit";
            break;
        }
        ret.push_back((parseHexDigits_(d1) << 4) + parseHexDigits_(d2));
    }
    return ret;
}

std::string readTilEOF(std::istream &f = std::cin)
{
    std::string s, ln;
    while (std::getline(f, ln)) {
        s += ln;
    }
    return s;
}

void bruteForceStrings(const std::function<void(const std::string &)> &callback,
                       const size_t maxLength = 15, const char min_ = '\0', const char max_ = 0xFF)
{
    for (size_t length = 1; length <= maxLength; ++length) {
        std::string current(length, min_);
        while (1) {
            callback(current);
            if (current == std::string(length, max_)) break;
            size_t i = length - 1;                      // max index
            while (i < length && current[i] == max_) {  // reset
                current[i] = min_;
                if (--i == 0) break;
            }
            ++current[i];
        }
    }
}
};  // namespace Debugging

#endif
