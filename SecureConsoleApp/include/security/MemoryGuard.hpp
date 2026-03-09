#pragma once
// ============================================================
// MemoryGuard.hpp — OS-level memory protection
// Standards: SEI CERT MEM06-C, OWASP Memory Management
// ============================================================
#include "SecureCore.hpp"
#ifndef _WIN32
  #include <sys/mman.h>
  #include <unistd.h>
  #include <cerrno>
  #include <cstring>
#else
  #include <windows.h>
#endif

namespace SecFW {

// ============================================================
// MemoryLocker: Lock memory pages out of swap (CERT MEM06-C)
// ============================================================
class MemoryLocker final {
public:
    [[nodiscard]] static Result<void> lock(const void* ptr, std::size_t size) noexcept {
#ifndef _WIN32
        if (::mlock(ptr, size) != 0)
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "mlock failed: " + std::string(std::strerror(errno)));
#else
        if (!VirtualLock(const_cast<void*>(ptr), size))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "VirtualLock failed: " + std::to_string(GetLastError()));
#endif
        return Result<void>::Success();
    }

    [[nodiscard]] static Result<void> unlock(const void* ptr, std::size_t size) noexcept {
#ifndef _WIN32
        if (::munlock(ptr, size) != 0)
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL, "munlock failed");
#else
        if (!VirtualUnlock(const_cast<void*>(ptr), size))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL, "VirtualUnlock failed");
#endif
        return Result<void>::Success();
    }
};

// SecureAllocator đã được định nghĩa trong SecureCore.hpp
using SecureByteVec = std::vector<byte_t, SecureAllocator<byte_t>>;
using SecureCharVec = std::vector<char,   SecureAllocator<char>>;

// ============================================================
// GuardedRegion: RAII — mlock on create, zero+munlock on destroy
// ============================================================
template<std::size_t N>
class GuardedRegion final {
public:
    GuardedRegion() {
        data_.fill(0);
        MemoryLocker::lock(data_.data(), N);
    }
    ~GuardedRegion() noexcept {
        volatile byte_t* p = data_.data();
        for (std::size_t i = 0; i < N; ++i) p[i] = 0;
        MemoryLocker::unlock(data_.data(), N);
    }
    GuardedRegion(const GuardedRegion&)            = delete;
    GuardedRegion& operator=(const GuardedRegion&) = delete;

    [[nodiscard]] byte_t*       data()       noexcept { return data_.data(); }
    [[nodiscard]] const byte_t* data() const noexcept { return data_.data(); }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return N; }

private:
    std::array<byte_t, N> data_;
};

// ============================================================
// MemoryGuard: Stack canary integrity check
// ============================================================
class MemoryGuard final {
public:
    static constexpr u32_t CANARY_VALUE = 0xDEADBEEF;

    MemoryGuard() noexcept : canary_(CANARY_VALUE) {}
    ~MemoryGuard() noexcept { volatile u32_t* p = &canary_; *p = 0; }

    [[nodiscard]] Result<void> checkIntegrity() const noexcept {
        if (canary_ != CANARY_VALUE)
            return Result<void>::Failure(SecurityStatus::ERR_TAMPER_DETECTED,
                "Stack canary corrupted — possible buffer overflow!");
        return Result<void>::Success();
    }

private:
    volatile u32_t canary_;
};

} // namespace SecFW
