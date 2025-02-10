#ifndef LIBCPPTLS_ENDIAN_UTILS_H
#define LIBCPPTLS_ENDIAN_UTILS_H

#include <cstddef>
#include <cstdint>
#include <type_traits>

constexpr auto UINT24_MAX = 0xFFFFFF;

template <typename T>
struct identity_type {
    typedef T type;
};

template <template <typename> typename WRAPPER_T, typename T, typename void_ = void>
struct try_wrap : public identity_type<T> {
};
template <template <typename> typename WRAPPER_T, typename T>
struct try_wrap<WRAPPER_T, T, std::void_t<WRAPPER_T<T>>> : public identity_type<WRAPPER_T<T>> {
};

template <template <typename> typename WRAPPER_T, typename T>
using try_wrap_type = typename try_wrap<WRAPPER_T, T>::type;

template <size_t s, typename... Ts>
struct nth_type : public identity_type<std::tuple_element_t<s, std::tuple<Ts...>>> {
};
template <size_t s, typename... Ts>
using nth_type_type = typename nth_type<s, Ts...>::type;

template <template <typename...> typename WRAPPER_T, typename void_, typename... Ts>
struct try_wrap_multi : public identity_type<nth_type_type<0, Ts...>> {
};

template <template <typename...> typename WRAPPER_T, typename... Ts>
struct try_wrap_multi<WRAPPER_T, std::void_t<WRAPPER_T<Ts...>>, Ts...>
    : public identity_type<nth_type_type<0, WRAPPER_T<Ts...>>> {
};

template <template <typename...> typename WRAPPER_T, typename... Ts>
using try_wrap_multi_type = typename try_wrap_multi<WRAPPER_T, Ts...>::type;

template <typename T>
using try_get_underlying_unsigned =
    try_wrap_type<std::make_unsigned_t, try_wrap_type<std::underlying_type_t, T>>;

template <typename T>
struct is_valid_endian_conversion_subject
    : public std::integral_constant<bool, std::is_integral_v<T> || std::is_enum_v<T>> {
};

template <typename T>
inline constexpr bool is_valid_endian_conversion_subject_v =
    is_valid_endian_conversion_subject<T>::value;

// copy to big endian, but dest_t must be a ptr
template <typename SRC_T, typename DEST_T,
          typename = std::enable_if_t<is_valid_endian_conversion_subject_v<std::decay_t<SRC_T>>>>
void copy_to_ptr_big_endian(SRC_T &&src, DEST_T *dest, size_t bytes = sizeof(std::decay_t<SRC_T>))
{
    if (bytes > sizeof(std::decay_t<SRC_T>)) bytes = sizeof(std::decay_t<SRC_T>);
    auto hostVal = static_cast<try_get_underlying_unsigned<std::decay_t<SRC_T>>>(src);
    auto ptr = reinterpret_cast<uint8_t *>(dest);
    for (decltype(bytes) offset = 0; offset < bytes; offset++)
        *(ptr + offset) = (hostVal >> 8 * (bytes - 1 - offset)) & 0xFF;
}

template <typename SRC_T>
auto to_big_endian(SRC_T &&src, size_t bytes = sizeof(std::decay_t<SRC_T>))
{
    using RET_T = try_get_underlying_unsigned<std::decay_t<SRC_T>>;
    RET_T ret = 0;
    copy_to_ptr_big_endian<decltype(src)>(std::forward<decltype(src)>(src), &ret, bytes);
    return ret;
}

template <typename SRC_T, typename DEST_T>
void stdcopy_to_big_endian(SRC_T &&src, DEST_T &&dest, size_t bytes = sizeof(std::decay_t<SRC_T>))
{
    auto be = to_big_endian(std::forward<decltype(src)>(src), bytes);
    auto beptr = reinterpret_cast<const uint8_t *>(&be);
    std::copy(beptr, beptr + bytes, dest);
}

template <typename RET_T_, size_t BYTES = sizeof(RET_T_), typename SRC_T,
          typename = std::enable_if_t<sizeof(RET_T_) / 2 < BYTES && BYTES <= sizeof(RET_T_) &&
                                      is_valid_endian_conversion_subject_v<RET_T_>>>
// NOTE: pass raw pointers instead of iterators
RET_T_ from_big_endian(const SRC_T *srcPtr)
{
    using UINT_T = try_get_underlying_unsigned<RET_T_>;
    auto ptr = reinterpret_cast<const uint8_t *>(srcPtr);
    UINT_T ret = 0;
    for (decltype(BYTES) offset = 0; offset < BYTES; offset++)
        ret |= *(ptr + offset) << 8 * (BYTES - 1 - offset);
    return static_cast<RET_T_>(ret);
}

#endif
