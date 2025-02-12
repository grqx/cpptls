#ifndef LIBCPPTLS_DEBUG_H
#define LIBCPPTLS_DEBUG_H

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

inline uint8_t parseHexDigits_(char c)
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

inline std::vector<uint8_t> parseBytesArray(std::string_view str)
{
    std::vector<uint8_t> ret;
    uint8_t cur = 0;
    bool hi = true;
    for (auto &&c : str)
        if (std::isxdigit(c)) {
            if (hi)
                cur = parseHexDigits_(c);
            else {
                cur = cur * 16 + parseHexDigits_(c);
                ret.push_back(cur);
            }
            hi = !hi;
        }
    return ret;
}

namespace BytesLiterals {
std::vector<uint8_t> operator"" _b(const char* str, size_t len) {
    return std::vector<uint8_t>(str, str + len);
}
// hex stream
std::vector<uint8_t> operator"" _hs(const char* str, size_t len) {
    return parseBytesArray({str, len});
}
};

inline std::string genCStyleArray(const std::vector<uint8_t> &vec)
{
    constexpr static auto m = "0123456789ABCDEF";
    std::string ret;
    for (auto &&c : vec) {
        ret += "0x";
        ret += m[(c >> 4) & 0x0F];
        ret += m[c & 0x0F];
        ret += ", ";
    }
    return ret;
}

inline std::string readTilEOF(std::istream &f = std::cin)
{
    std::string s, ln;
    while (std::getline(f, ln)) {
        s += ln;
    }
    return s;
}

inline void bruteForceStrings(const std::function<void(const std::string &)> &callback,
                              const size_t maxLength = 15, const char min_ = '\0',
                              const char max_ = 0xFF)
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
