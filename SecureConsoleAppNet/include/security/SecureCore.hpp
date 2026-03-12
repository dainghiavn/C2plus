#pragma once
// ============================================================
// SecureCore.hpp — v1.4
// Foundation types for the SecFW security framework.
//
// v1.4 Changes (Pre-Network Hardening):
//   FIX [BUG-E01]: Add network error codes to SecurityStatus:
//                  ERR_NETWORK_FAIL, ERR_TIMEOUT,
//                  ERR_PEER_REJECTED, ERR_CONN_CLOSED
//                  Previously all network errors mapped to ERR_INTERNAL,
//                  losing diagnostic information and breaking retry logic.
//
// Provides:
//   - byte_t / u32_t / u64_t    type aliases
//   - SecBytes                   secure-zeroing byte vector
//   - SecureString               secure-zeroing string wrapper
//   - SecurityStatus             error code enum (extended in v1.4)
//   - Result<T>                  monadic result type (no exceptions)
//   - Roles                      bitmask namespace for RBAC
//   - secureZero()               wipe arbitrary memory safely
//
// Standards:
//   CERT MEM03-C, MEM06-C (zero sensitive buffers before free)
//   CERT MSC41-C           (no hard-coded credentials in types)
//   OWASP ASVS V2 / V6    (memory hygiene)
// ============================================================

#include <cstdint>
#include <cstring>
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
// buffer upon destruction. Deliberately non-copyable; move is allowed.

class SecureString {
public:
    SecureString() = default;

    explicit SecureString(const std::string& s) : data_(s) {}
    explicit SecureString(std::string_view sv)  : data_(sv) {}

    // Move: source is wiped after transfer
    SecureString(SecureString&& other) noexcept
        : data_(std::move(other.data_)) { other.wipe(); }

    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            wipe();
            data_ = std::move(other.data_);
            other.wipe();
        }
        return *this;
    }

    // Non-copyable — prevent accidental duplication of secrets
    SecureString(const SecureString&)            = delete;
    SecureString& operator=(const SecureString&) = delete;

    ~SecureString() { wipe(); }

    [[nodiscard]] std::string_view view()  const noexcept { return data_; }
    [[nodiscard]] const std::string& str() const noexcept { return data_; }
    [[nodiscard]] bool        empty()      const noexcept { return data_.empty(); }
    [[nodiscard]] std::size_t size()       const noexcept { return data_.size(); }

    void append(char c)              { data_ += c; }
    void append(std::string_view sv) { data_.append(sv); }

    void wipe() noexcept {
        if (!data_.empty()) {
            volatile char* p = data_.data();
            for (std::size_t i = 0; i < data_.size(); ++i) p[i] = '\0';
            data_.clear();
        }
    }

    // clear() is an alias for wipe() — CERT MEM03-C
    void clear() noexcept { wipe(); }

private:
    std::string data_;
};

// ── SecurityStatus ────────────────────────────────────────────────────────────
//
// Canonical error codes used throughout the framework.
//
// v1.4: Added network-specific codes (7-10) to enable precise error
// handling and retry logic in upcoming IPC/TLS layers.
// All existing codes (0-6) are unchanged — full backward compatibility.
//
// Naming convention:
//   ERR_*_FAIL    — operation failed, caller should retry or abort
//   ERR_*_CLOSED  — connection ended by peer (not an error per se)
//   ERR_TIMEOUT   — operation exceeded time limit, may retry
//   ERR_PEER_*    — remote side rejected or violated protocol

enum class SecurityStatus : int {
    // ── Existing codes (v1.3) — DO NOT RENUMBER ──────────────────────────
    OK                  = 0,
    ERR_AUTH_FAILED     = 1,   // bad credentials / expired session
    ERR_CRYPTO_FAIL     = 2,   // OpenSSL / key derivation error
    ERR_INPUT_INVALID   = 3,   // validation / sanitisation failure
    ERR_TAMPER_DETECTED = 4,   // debugger, HMAC mismatch, etc.
    ERR_CONFIG_INVALID  = 5,   // malformed or missing config
    ERR_INTERNAL        = 6,   // unexpected / unclassified internal error

    // ── New in v1.4: Network / IPC codes ─────────────────────────────────
    //
    // BUG-E01 FIX: Previously all of the below were silently reported as
    // ERR_INTERNAL, making it impossible to distinguish a configuration
    // error (e.g. wrong socket path) from a transient network hiccup or a
    // deliberate peer rejection.  Callers can now implement correct retry
    // logic: retry on ERR_TIMEOUT / ERR_CONN_CLOSED, abort on ERR_NETWORK_FAIL
    // or ERR_PEER_REJECTED.

    ERR_NETWORK_FAIL    = 7,   // socket/bind/connect/listen syscall failed
                               // (check errno for OS-level detail)

    ERR_TIMEOUT         = 8,   // recv/send/connect exceeded configured timeout
                               // — transient, may retry with backoff

    ERR_PEER_REJECTED   = 9,   // peer authentication failed (wrong UID/GID,
                               // bad token, mTLS cert mismatch, etc.)
                               // — NOT transient, do not retry blindly

    ERR_CONN_CLOSED     = 10,  // peer closed connection cleanly (EOF / SHUT_WR)
                               // — may indicate normal end-of-stream or
                               //   unexpected disconnect; caller decides
};

// ── statusMessage — human-readable description ────────────────────────────────
//
// Returns a static string; never allocates. Safe to call from signal handlers
// (read-only, no dynamic dispatch, no heap).

[[nodiscard]] inline const char* statusMessage(SecurityStatus s) noexcept {
    switch (s) {
        case SecurityStatus::OK:                  return "OK";
        case SecurityStatus::ERR_AUTH_FAILED:     return "Authentication failed";
        case SecurityStatus::ERR_CRYPTO_FAIL:     return "Cryptographic error";
        case SecurityStatus::ERR_INPUT_INVALID:   return "Input validation error";
        case SecurityStatus::ERR_TAMPER_DETECTED: return "Tamper detected";
        case SecurityStatus::ERR_CONFIG_INVALID:  return "Configuration invalid";
        case SecurityStatus::ERR_INTERNAL:        return "Internal error";
        // v1.4 network codes:
        case SecurityStatus::ERR_NETWORK_FAIL:    return "Network operation failed";
        case SecurityStatus::ERR_TIMEOUT:         return "Operation timed out";
        case SecurityStatus::ERR_PEER_REJECTED:   return "Peer authentication rejected";
        case SecurityStatus::ERR_CONN_CLOSED:     return "Connection closed by peer";
        default:                                  return "Unknown error";
    }
}

// ── isNetworkError — convenience predicate ────────────────────────────────────
//
// Returns true for any v1.4 network-layer error code.
// Useful for callers that want to handle all network errors uniformly
// without enumerating each code.

[[nodiscard]] inline bool isNetworkError(SecurityStatus s) noexcept {
    return s == SecurityStatus::ERR_NETWORK_FAIL
        || s == SecurityStatus::ERR_TIMEOUT
        || s == SecurityStatus::ERR_PEER_REJECTED
        || s == SecurityStatus::ERR_CONN_CLOSED;
}

// ── isRetryable — should the caller attempt to retry? ────────────────────────
//
// Conservative policy:
//   Retry on: ERR_TIMEOUT, ERR_CONN_CLOSED (peer may have restarted)
//   Do NOT retry on: auth/tamper/peer-rejection (security violations)
//   Do NOT retry on: crypto/config (programming/configuration errors)

[[nodiscard]] inline bool isRetryable(SecurityStatus s) noexcept {
    return s == SecurityStatus::ERR_TIMEOUT
        || s == SecurityStatus::ERR_CONN_CLOSED;
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
        r.status = SecurityStatus::OK;
        r.value  = std::move(v);
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
        if (s.empty())        s  = "NONE";
        while (!s.empty() && s.back() == ' ') s.pop_back();
        return s;
    }
} // namespace Roles

// ── secureZero — wipe arbitrary memory (not optimised away) ──────────────────
//
// Uses volatile pointer to prevent the compiler from eliding the wipe.
// Caller is responsible for ensuring [ptr, ptr+n) is valid writable memory.
// Safe to call on stack or heap; does NOT free the memory.

inline void secureZero(void* ptr, std::size_t n) noexcept {
    if (!ptr || n == 0) return;
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (std::size_t i = 0; i < n; ++i) p[i] = 0;
}

} // namespace SecFW
