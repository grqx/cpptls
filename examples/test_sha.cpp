#include <cpptls/crypto/hash/sha1.h>
#include <cpptls/crypto/hash/sha256.h>
#include <cpptls/crypto/hash/sha512.h>
#include <cpptls/export.h>

#include <iomanip>
#include <iostream>
#include <string>

constexpr auto hex = "0123456789abcdef";

int main()
{
    auto phex = [](std::vector<uint8_t> v) {
        for (auto &&c : v) {
            std::cout << hex[c >> 4 & 0xf] << hex[c & 0xf];
        }
    };
    std::string str;
    while (std::cin >> str) {
        HashAlgo_SHA512 s512;
        s512.update(str);
        std::cout << "SHA512 digest of " << std::quoted(str) << " is: " << s512.hexdigest() << '\n';
        std::cout << "SHA384 digest of " << std::quoted(str) << " is: ";
        phex(HashAlgo_SHA384::calculate({str.data(), str.data() + str.size()}));
        std::cout << '\n';
        HashAlgo_SHA256 s256;
        s256.update(str);
        std::cout << "SHA256 digest of " << std::quoted(str) << " is: " << s256.hexdigest() << '\n';
        auto s1h = SHA1_calculate({str.data(), str.data() + str.size()});
        std::cout << "SHA1 digest of " << std::quoted(str) << " is: ";
        phex(s1h);
        std::cout << '\n';
    }
    return 0;
}