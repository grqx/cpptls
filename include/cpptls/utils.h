#ifndef LIBCPPTLS_UTILS_H
#define LIBCPPTLS_UTILS_H

#include <string_view>

constexpr bool ends_with(std::string_view str, std::string_view suffix)
{
    if (suffix.size() > str.size()) return false;
    for (size_t i = 1; i <= suffix.size(); ++i)
        if (str[str.size() - i] != suffix[suffix.size() - i]) return false;
    return true;
}

#endif
