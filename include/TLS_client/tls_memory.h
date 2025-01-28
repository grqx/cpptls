#ifndef TLS_CLIENT_TLS_MEMORY_H
#define TLS_CLIENT_TLS_MEMORY_H
#include <memory>
template <typename T>
using unique_ptr_with_deleter = std::unique_ptr<T, std::function<void(T*)>>;
#endif
