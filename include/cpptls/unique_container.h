#ifndef LIBCPPTLS_UNIQUE_CONTAINER_H
#define LIBCPPTLS_UNIQUE_CONTAINER_H
#ifndef NDEBUG
#include <iostream>
#endif
#include <vector>
#include <iterator>
#include <utility>
#include <type_traits>
#include <cstddef>

template <typename T, template <typename...> typename Container = std::vector>
class UniqueContainer final : public Container<T> {
public:
    constexpr UniqueContainer(T &&t) : Container<T>() {
        #ifndef NDEBUG
        std::cout << "One-element constructor\n";
        #endif
        this->push_back(std::move(t));
    }
    constexpr UniqueContainer() : Container<T>() {
        std::cout << "constructor without arguments\n";
    }
    template <typename ...Args, typename = std::enable_if_t<(std::is_same_v<T, std::decay_t<Args>> && ...)>>
    constexpr UniqueContainer(Args &&...args) : Container<T>{} {
        #ifndef NDEBUG
        std::cout << "Variadic template\n";
        #endif
        if constexpr (std::is_same_v<Container<T>, std::vector<T>>) {
            this->reserve(sizeof...(args));
        }
        (this->push_back(std::move(args)), ...);
    }
    template <typename ITER_T, typename = std::enable_if_t<!std::is_same_v<T, ITER_T>>>
    constexpr UniqueContainer(ITER_T &&first, ITER_T &&last) : Container<T>(std::make_move_iterator(std::forward<decltype(first)>(first)),
            std::make_move_iterator(std::forward<decltype(last)>(last)))
    {
        #ifndef NDEBUG
        std::cout << "Iterator constructor\n";
        #endif
    }
    template <typename STORAGE_T, typename = std::enable_if_t<!std::is_convertible_v<std::decay_t<STORAGE_T>, T>>>
    constexpr UniqueContainer(STORAGE_T &&arg)
        : Container<T>(std::make_move_iterator(std::begin(arg)), std::make_move_iterator(std::end(arg)))
    {
        #ifndef NDEBUG
        std::cout << "Other storage class constructor\n";
        #endif
    }

    UniqueContainer(const UniqueContainer&) = delete;
    UniqueContainer& operator=(const UniqueContainer&) = delete;
    UniqueContainer(UniqueContainer&& other) noexcept = default;
    UniqueContainer& operator=(UniqueContainer&& other) noexcept = default;
};

#endif
