#pragma once
// ============================================================
// SecureCore.hpp - Foundation Security Primitives
// Standards: SEI CERT C++ MSC50-CPP, MEM50-CPP, INT30-C
// ============================================================
#include <array>
#include <memory>
#include <cstring>
#include <type_traits>
#include <stdexcept>
#include <string_view>
#include <span>
#include <string>
#include <vector>
#include <limits>
#include <algorithm>
#include <optional>
#include <cstdint>

namespace SecFW {

using byte_t   = std::uint8_t;
using u32_t    = std::uint32_t;
using u64_t    = std::uint64_t;
using i32_t    = std::int32_t;
using i64_t    = std::int64_t;
using SecBytes = std::vector<byte_t>;

// ============================================================
// SecureAllocator: STL allocator that zeros memory on dealloc
// ============================================================
template<typename T>
class SecureAllocator {
public:
    using value_type = T;
    SecureAllocator() noexcept = default;
    template<typename U> SecureAllocator(const SecureAllocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t n) {
        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) throw std::bad_alloc();
        return static_cast<T*>(::operator new(n * sizeof(T)));
    }
    void deallocate(T* ptr, std::size_t n) noexcept {
        if (ptr) {
            volatile T* vptr = ptr;
            for (std::size_t i = 0; i < n; ++i) vptr[i] = T{};
        }
        ::operator delete(ptr);
    }
    template<typename U> bool operator==(const SecureAllocator<U>&) const noexcept { return true; }
    template<typename U> bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

// ============================================================
// SecureString: auto-wipe on destruct (CERT STR31-C) using SecureAllocator
// ============================================================
class SecureString {
public:
    using value_type = char;
    using allocator_type = SecureAllocator<char>;
    using container_type = std::vector<char, allocator_type>;

    SecureString() = default;
    explicit SecureString(std::string_view sv) : data_(sv.begin(), sv.end()) {}
    SecureString(const char* s) : SecureString(std::string_view(s)) {}
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    SecureString(SecureString&&) noexcept = default;
    SecureString& operator=(SecureString&&) noexcept = default;

    ~SecureString() noexcept { clear(); }

    void clear() noexcept {
        if (!data_.empty()) {
            volatile char* p = data_.data();
            for (std::size_t i = 0; i < data_.size(); ++i) p[i] = 0;
            data_.clear();
        }
    }

    [[nodiscard]] std::string_view view() const noexcept { return {data_.data(), data_.size()}; }
    [[nodiscard]] const char* c_str() const noexcept { return data_.data(); }
    [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }

    // Constant-time comparison (CERT MSC39-C)
    [[nodiscard]] bool secureEquals(const SecureString& other) const noexcept {
        if (data_.size() != other.data_.size()) return false;
        volatile int diff = 0;
        for (std::size_t i = 0; i < data_.size(); ++i)
            diff |= (data_[i] ^ other.data_[i]);
        return diff == 0;
    }

    // Implicit conversion to std::string_view (use with caution)
    [[nodiscard]] operator std::string_view() const noexcept { return view(); }

private:
    container_type data_;
};

// Helper to zero memory (volatile-safe)
template<typename T>
inline void secureZero(T& obj) noexcept {
    volatile T* p = &obj;
    *p = T{};
}

template<typename T>
inline void secureZero(T* ptr, std::size_t count) noexcept {
    volatile T* vptr = ptr;
    for (std::size_t i = 0; i < count; ++i) vptr[i] = T{};
}

// ============================================================
// SecureBuffer: zero-on-destruct (CERT MEM03-C)
// ============================================================
template<std::size_t N>
class SecureBuffer final {
public:
    SecureBuffer() noexcept { data_.fill(0); }
    ~SecureBuffer() noexcept { secureZero(data_.data(), N); }
    SecureBuffer(const SecureBuffer&)            = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&&) noexcept            = default;
    SecureBuffer& operator=(SecureBuffer&&) noexcept = default;

    [[nodiscard]] byte_t*       data()       noexcept { return data_.data(); }
    [[nodiscard]] const byte_t* data() const noexcept { return data_.data(); }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return N; }
    [[nodiscard]] std::span<byte_t, N>  span()       noexcept { return data_; }

private:
    std::array<byte_t, N> data_;
};

// ============================================================
// SecurityStatus & Result<T> (CERT ERR51-CPP)
// ============================================================
enum class SecurityStatus : i32_t {
    OK                  =  0,
    ERR_INPUT_INVALID   = -1,
    ERR_AUTH_FAILED     = -2,
    ERR_CRYPTO_FAIL     = -3,
    ERR_ACCESS_DENIED   = -4,
    ERR_RATE_LIMITED    = -5,
    ERR_TAMPER_DETECTED = -6,
    ERR_CONFIG_INVALID  = -7,
    ERR_INTERNAL        = -99
};

template<typename T>
struct Result {
    T              value{};
    SecurityStatus status{ SecurityStatus::OK };
    std::string    message{};

    [[nodiscard]] bool ok()   const noexcept { return status == SecurityStatus::OK; }
    [[nodiscard]] bool fail() const noexcept { return !ok(); }

    static Result<T> Success(T val) {
        return { std::move(val), SecurityStatus::OK, "" };
    }
    static Result<T> Failure(SecurityStatus s, std::string msg) {
        return { T{}, s, std::move(msg) };
    }
};

template<>
struct Result<void> {
    SecurityStatus status{ SecurityStatus::OK };
    std::string    message{};

    [[nodiscard]] bool ok()   const noexcept { return status == SecurityStatus::OK; }
    [[nodiscard]] bool fail() const noexcept { return !ok(); }

    static Result<void> Success() { return { SecurityStatus::OK, "" }; }
    static Result<void> Failure(SecurityStatus s, std::string msg) {
        return { s, std::move(msg) };
    }
};

// Role bitmask
namespace Roles {
    constexpr u32_t GUEST    = 0x01;
    constexpr u32_t USER     = 0x02;
    constexpr u32_t OPERATOR = 0x04;
    constexpr u32_t ADMIN    = 0x08;
    constexpr u32_t SUPER    = 0xFF;
}

} // namespace SecFW
