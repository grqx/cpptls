#ifndef LIBCPPTLS_TLS_MEMORY_H
#define LIBCPPTLS_TLS_MEMORY_H
#include <functional>
#include <memory>
// TODO: maybe use a macro with decltype instead
template <typename T>
using unique_ptr_with_deleter = std::unique_ptr<T, std::function<void(T *)>>;

template <typename T>
using unique_ptr_with_fnptr_deleter = std::unique_ptr<T, void (*)(T *)>;
#endif
