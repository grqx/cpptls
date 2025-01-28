#ifndef TLS_CLIENT_SIMPLE_SPAN_H
#define TLS_CLIENT_SIMPLE_SPAN_H
#include <cstddef>

template <typename T>
class SimpSpan {
private:
    T* data_;
    size_t size_;

public:
    SimpSpan() noexcept : data_(nullptr), size_(0) {}
    SimpSpan(decltype(nullptr) nptr) noexcept : data_(nullptr), size_(0)
    {
        static_assert(nptr == nullptr, "nptr must be equal to nullptr");
    }
    explicit SimpSpan(T* ptr_start, T* ptr_end) noexcept : data_(ptr_start), size_(ptr_end - ptr_start) {}

    template <size_t N>
    SimpSpan(T (&arr)[N]) noexcept : data_(arr), size_(N) {}

    template <typename Container>
    SimpSpan(Container& cont) noexcept : data_(cont.data()), size_(cont.size()) {}

    T* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }

    // Element Access
    T& operator[](size_t index) const { return data_[index]; }
    T& front() const { return data_[0]; }
    T& back() const { return data_[size_ - 1]; }

    // Iterators
    T* begin() const noexcept { return data_; }
    T* end() const noexcept { return data_ + size_; }
    operator bool() const noexcept { return data_ != nullptr; }
};

#endif
