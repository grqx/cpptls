#ifndef TLS_CLIENT_MACROS_H
#define TLS_CLIENT_MACROS_H

#define DEPRECATION_START inline namespace [[deprecated]] Deprecated {
#define DEPRECATION_END }

#if defined(_MSC_VER) && !defined(__clang__)
#define DISABLE_DEPRECATION_WARNING_START __pragma(warning(push)) __pragma(warning(disable : 4996))
#define DISABLE_DEPRECATION_WARNING_END __pragma(warning(pop))

#elif defined(__GNUC__) || defined(__clang__)
#define DISABLE_DEPRECATION_WARNING_START \
    _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#define DISABLE_DEPRECATION_WARNING_END _Pragma("GCC diagnostic pop")
#else
#define DISABLE_DEPRECATION_WARNING_START
#define DISABLE_DEPRECATION_WARNING_END
#endif

#if defined(__cpp_lib_unreachable) && __cpp_lib_unreachable >= 202202L
#include <utility>
#define UNREACHABLE std::unreachable()
#elif defined(_MSC_VER) && !defined(__clang__)  // MSVC
#define UNREACHABLE __assume(false)
#elif defined(__GNUC__) || defined(__clang__)  // GCC, Clang
#define UNREACHABLE __builtin_unreachable()
#else
#define UNREACHABLE
#endif

#if defined(__cpp_lib_to_underlying) && __cpp_lib_to_underlying >= 202102L
#include <utility>
#define UNDERLYING(ENUM_VAL) std::to_underlying(ENUM_VAL)
#else
#include <type_traits>
#define UNDERLYING(ENUM_VAL) static_cast<std::underlying_type_t<decltype(ENUM_VAL)>>(ENUM_VAL)
#endif

#define NAMEOF(...) #__VA_ARGS__

#endif
