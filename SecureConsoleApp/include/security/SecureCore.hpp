#pragma once
// ============================================================
// SecureCore.hpp — v1.3
// Foundation types for the SecFW security framework.
//
// Provides:
//   - byte_t / u32_t          type aliases
//   - SecBytes                 secure-zeroing byte vector
//   - SecureString             secure-zeroing string wrapper
//   - SecurityStatus           error code enum
//   - Result<T>                monadic result type (no exceptions)
//   - Roles                    bitmask namespace for RBAC
//
// Standards:
//   CERT MEM03-C, MEM06-C (zero sensitive buffers before free)
//   CERT MSC41-C           (no hard-coded credentials in types)
//   OWASP ASVS V2 / V6     (memory hygiene)
// ============================================================

#include <cstdint>
#include <cstring>       // memset
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <limits>
#include <stdexcept>
#include <span>

namespace SecFW {

// ── Primitive aliases ─────────────────────────────────────────────────────────

using byte_t = unsigned char;
using u32_t  = std::uint32_t;
using u64_t  = std::uint64_t;

// ── Secure allocator (CERT MEM03-C / MEM06-C) ────────────────────────────────
//
// Zeros the memory region before deallocating so sensitive data is never
// left readable in freed heap pages.

template <typename T>
struct SecureAllocator {
    using value_type = T;

    SecureAllocator() noexcept = default;

    template <typename U>
    explicit SecureAllocator(const SecureAllocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t n) {
        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
            throw std::bad_alloc();
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        T* p = static_cast<T*>(::operator new(n * sizeof(T)));
        if (!p) throw std::bad_alloc();
        return p;
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (p && n > 0) {
            // Volatile write prevents compiler from eliding the wipe (CERT MEM03-C)
            volatile T* vp = p;
            for (std::size_t i = 0; i < n; ++i) vp[i] = T{};
        }
        ::operator delete(p);
    }

    template <typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }

    template <typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

// ── SecBytes — secure-zeroing byte buffer ─────────────────────────────────────

using SecBytes = std::vector<byte_t, SecureAllocator<byte_t>>;

// ── SecureString — secure-zeroing std::string wrapper ────────────────────────
//
// Holds a sensitive string (password, key material) and wipes the internal
// buffer upon destruction.  Deliberately non-copyable; move is allowed.

class SecureString {
public:
    SecureString() = default;

    // Construct from existing string — copies the data
    explicit SecureString(const std::string& s)
        : data_(s) {}

    explicit SecureString(std::string_view sv)
        : data_(sv) {}

    // Move constructor / assignment — source is wiped
    SecureString(SecureString&& other) noexcept
        : data_(std::move(other.data_)) {
        other.wipe();
    }

    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            wipe();
            data_ = std::move(other.data_);
            other.wipe();
        }
        return *this;
    }

    // Non-copyable — prevent accidental duplication of secrets
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    ~SecureString() { wipe(); }

    [[nodiscard]] std::string_view view() const noexcept { return data_; }
    [[nodiscard]] const std::string& str()  const noexcept { return data_; }
    [[nodiscard]] bool  empty()             const noexcept { return data_.empty(); }
    [[nodiscard]] std::size_t size()        const noexcept { return data_.size(); }

    // Append more data (e.g. reading a password character by character)
    void append(char c) { data_ += c; }
    void append(std::string_view sv) { data_.append(sv); }

    void wipe() noexcept {
        if (!data_.empty()) {
            volatile char* p = data_.data();
            for (std::size_t i = 0; i < data_.size(); ++i) p[i] = '\0';
            data_.clear();
        }
    }

private:
    std::string data_;
};

// ── SecurityStatus ────────────────────────────────────────────────────────────
//
// Canonical error codes used throughout the framework.

enum class SecurityStatus : int {
    OK                  = 0,
    ERR_AUTH_FAILED     = 1,   // bad credentials / expired session
    ERR_CRYPTO_FAIL     = 2,   // OpenSSL / key derivation error
    ERR_INPUT_INVALID   = 3,   // validation / sanitisation failure
    ERR_TAMPER_DETECTED = 4,   // debugger, HMAC mismatch, etc.
    ERR_CONFIG_INVALID  = 5,   // malformed or missing config
    ERR_INTERNAL        = 6,   // unexpected / unclassified
};

[[nodiscard]] inline const char* statusMessage(SecurityStatus s) noexcept {
    switch (s) {
        case SecurityStatus::OK:                  return "OK";
        case SecurityStatus::ERR_AUTH_FAILED:     return "Authentication failed";
        case SecurityStatus::ERR_CRYPTO_FAIL:     return "Cryptographic error";
        case SecurityStatus::ERR_INPUT_INVALID:   return "Input validation error";
        case SecurityStatus::ERR_TAMPER_DETECTED: return "Tamper detected";
        case SecurityStatus::ERR_CONFIG_INVALID:  return "Configuration invalid";
        case SecurityStatus::ERR_INTERNAL:        return "Internal error";
        default:                                  return "Unknown error";
    }
}

// ── Result<T> — monadic result (no exceptions for security paths) ─────────────
//
// Modeled after Rust's Result<T, E>; avoids exception-based control flow
// which can leak timing information and complicate auditing.
//
// Usage:
//   Result<SecBytes> r = CryptoEngine::randomBytes(32);
//   if (r.fail()) { /* handle r.message */ }
//   SecBytes bytes = std::move(r.value);

template <typename T>
struct Result {
    SecurityStatus status  { SecurityStatus::OK };
    std::string    message {};
    T              value   {};

    [[nodiscard]] bool ok()   const noexcept { return status == SecurityStatus::OK; }
    [[nodiscard]] bool fail() const noexcept { return status != SecurityStatus::OK; }

    [[nodiscard]] static Result<T> Success(T v) {
        Result<T> r;
        r.status  = SecurityStatus::OK;
        r.value   = std::move(v);
        return r;
    }

    [[nodiscard]] static Result<T> Failure(SecurityStatus s, std::string msg) {
        Result<T> r;
        r.status  = s;
        r.message = std::move(msg);
        return r;
    }
};

// Specialisation for Result<void> — no value field needed
template <>
struct Result<void> {
    SecurityStatus status  { SecurityStatus::OK };
    std::string    message {};

    [[nodiscard]] bool ok()   const noexcept { return status == SecurityStatus::OK; }
    [[nodiscard]] bool fail() const noexcept { return status != SecurityStatus::OK; }

    [[nodiscard]] static Result<void> Success() {
        return { SecurityStatus::OK, {} };
    }

    [[nodiscard]] static Result<void> Failure(SecurityStatus s, std::string msg) {
        return { s, std::move(msg) };
    }
};

// ── Roles — RBAC bitmask flags ────────────────────────────────────────────────
//
// Stored as u32_t; roles are combined with bitwise OR.
// Checked with bitwise AND:  if (session.roleFlags & Roles::ADMIN) { … }
//
// Hierarchy (informational only — enforcement is per-command):
//   SUPER > ADMIN > OPERATOR > USER > GUEST

namespace Roles {
    static constexpr u32_t GUEST    = 0x0001u;   // read-only / unauthenticated
    static constexpr u32_t USER     = 0x0002u;   // standard authenticated user
    static constexpr u32_t OPERATOR = 0x0004u;   // elevated operational rights
    static constexpr u32_t ADMIN    = 0x0008u;   // full administrative access
    static constexpr u32_t SUPER    = 0x0010u;   // superuser (system-level ops)

    [[nodiscard]] inline std::string format(u32_t flags) {
        if (flags & SUPER)    return "SUPER";
        std::string s;
        if (flags & ADMIN)    s += "ADMIN ";
        if (flags & OPERATOR) s += "OPERATOR ";
        if (flags & USER)     s += "USER ";
        if (flags & GUEST)    s += "GUEST";
        if (s.empty())        s = "NONE";
        // trim trailing space
        while (!s.empty() && s.back() == ' ') s.pop_back();
        return s;
    }
}

} // namespace SecFW
