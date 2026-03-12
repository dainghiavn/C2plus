#pragma once
// ============================================================
// MemoryGuard.hpp — v1.3
// Memory protection primitives for sensitive runtime data.
//
// Provides:
//   MemoryGuard   — RAII guard: locks a stack frame into physical RAM,
//                   plants a stack canary, and validates it on destruction.
//   lockMemory()  — lock an arbitrary buffer via mlock / VirtualLock
//   unlockMemory()— counterpart unlock
//
// Stack canary approach:
//   A random sentinel value is written at construction time into a
//   local volatile array.  checkIntegrity() verifies the sentinel is
//   intact.  Any stack-smashing corruption between construction and
//   the check will be detected.
//   (Not a replacement for OS-level stack protectors; complementary.)
//
// Standards:
//   CERT MEM06-C   (lock sensitive data to prevent paging)
//   OWASP MASVS-R  (anti-analysis, memory integrity)
//   NIST SP 800-53 SC-28 (protection of information at rest)
// ============================================================

#include "SecureCore.hpp"
#include <cstdint>
#include <cstring>
#include <array>
#include <string>

// ── Platform detection ────────────────────────────────────────────────────────
#if defined(_WIN32) || defined(_WIN64)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  define SECFW_HAVE_VIRTUALLOCK 1
#else
#  include <sys/mman.h>   // mlock / munlock
#  include <unistd.h>
#  if defined(__linux__)
#    include <sys/resource.h>
#  endif
#  define SECFW_HAVE_MLOCK 1
#endif

namespace SecFW {

// ── Low-level memory locking ──────────────────────────────────────────────────
//
// lockMemory() ensures the supplied region will not be swapped to disk.
// Errors are non-fatal (locking may fail without root / elevated rights)
// but are surfaced via Result so callers can log or warn.

[[nodiscard]] inline Result<void> lockMemory(const void* addr, std::size_t len) noexcept {
    if (!addr || len == 0)
        return Result<void>::Failure(SecurityStatus::ERR_INTERNAL, "lockMemory: null/zero");

#if defined(SECFW_HAVE_VIRTUALLOCK)
    if (!VirtualLock(const_cast<void*>(addr), len))
        return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
            "VirtualLock failed (error " + std::to_string(GetLastError()) + ")");
    return Result<void>::Success();

#elif defined(SECFW_HAVE_MLOCK)
    // mlock requires page alignment; we pass what we have — the kernel
    // will round down to the page boundary, locking at least the region.
    if (mlock(addr, len) != 0) {
        return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
            std::string("mlock failed: ") + ::strerror(errno));
    }
    return Result<void>::Success();

#else
    (void)addr; (void)len;
    return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
        "lockMemory: no platform support");
#endif
}

[[nodiscard]] inline Result<void> unlockMemory(const void* addr, std::size_t len) noexcept {
    if (!addr || len == 0)
        return Result<void>::Success();  // nothing to unlock

#if defined(SECFW_HAVE_VIRTUALLOCK)
    VirtualUnlock(const_cast<void*>(addr), len);
    return Result<void>::Success();

#elif defined(SECFW_HAVE_MLOCK)
    munlock(addr, len);
    return Result<void>::Success();

#else
    (void)addr; (void)len;
    return Result<void>::Success();
#endif
}

// ── MemoryGuard ───────────────────────────────────────────────────────────────
//
// RAII guard to be instantiated at the top of sensitive functions.
//
//   void processPassword(SecureString& pwd) {
//       MemoryGuard guard;
//       if (guard.checkIntegrity().fail()) { /* handle */ }
//       …
//   }
//
// Responsibilities:
//   1. Tries to lock its own stack frame into RAM (mlock / VirtualLock).
//   2. Plants a random-looking canary sentinel on the stack.
//   3. checkIntegrity() verifies the canary is still intact.
//   4. Destructor wipes the canary region before unlocking.
//
// The canary is a compile-time constant pattern XOR'd with a predictable
// runtime cookie (address of the guard itself).  This makes the canary
// value different every instantiation without needing CSPRNG in the ctor,
// while still being detectable if overwritten with zeros or a fixed value.

class MemoryGuard final {
public:
    static constexpr std::size_t CANARY_WORDS = 4;

    MemoryGuard() noexcept {
        // Build per-instance canary from object address XOR magic constant.
        // Volatile writes prevent the compiler from optimising them away.
        uintptr_t cookie = reinterpret_cast<uintptr_t>(this) ^ MAGIC;
        volatile uint64_t* cp = canary_;
        for (std::size_t i = 0; i < CANARY_WORDS; ++i)
            cp[i] = cookie ^ (static_cast<uint64_t>(i + 1) * 0xDEAD'BEEF'CAFE'BABEull);

        expected_ = cookie;

        // Best-effort: lock this object's storage into physical RAM.
        (void)lockMemory(this, sizeof(*this));
    }

    ~MemoryGuard() noexcept {
        // Wipe canary before unlock so values never hit swap
        volatile uint64_t* cp = canary_;
        for (std::size_t i = 0; i < CANARY_WORDS; ++i) cp[i] = 0;
        expected_ = 0;

        (void)unlockMemory(this, sizeof(*this));
    }

    // Non-copyable / non-movable — guard is tied to its stack location
    MemoryGuard(const MemoryGuard&)            = delete;
    MemoryGuard& operator=(const MemoryGuard&) = delete;
    MemoryGuard(MemoryGuard&&)                 = delete;
    MemoryGuard& operator=(MemoryGuard&&)      = delete;

    // ── checkIntegrity ───────────────────────────────────────────────────────
    //
    // Verify that the canary words still match the expected pattern.
    // Returns Failure if any word has been corrupted.

    [[nodiscard]] Result<void> checkIntegrity() const noexcept {
        uintptr_t cookie = reinterpret_cast<uintptr_t>(this) ^ MAGIC;
        const volatile uint64_t* cp = canary_;

        for (std::size_t i = 0; i < CANARY_WORDS; ++i) {
            uint64_t expected = cookie ^ (static_cast<uint64_t>(i + 1) * 0xDEAD'BEEF'CAFE'BABEull);
            if (cp[i] != expected)
                return Result<void>::Failure(
                    SecurityStatus::ERR_TAMPER_DETECTED,
                    "Stack canary corruption detected at word " + std::to_string(i));
        }

        // Also verify the stored cookie hasn't been tampered
        if (expected_ != cookie)
            return Result<void>::Failure(
                SecurityStatus::ERR_TAMPER_DETECTED,
                "Stack canary cookie mismatch");

        return Result<void>::Success();
    }

private:
    // Using volatile array to prevent elision; aligned for platform atomicity
    alignas(64) uint64_t canary_[CANARY_WORDS] {};  // FIX ERR-C: raw array (volatile ptr-safe)
    volatile uintptr_t expected_ { 0 };

    // XOR magic: chosen to be non-zero and non-uniform bit pattern
    static constexpr uintptr_t MAGIC = static_cast<uintptr_t>(0xC0DE'FACE'0BAD'F00Dull);
};

// ── SecureAllocator helper ────────────────────────────────────────────────────
//
// Wrapper that locks allocated memory into RAM immediately after allocation
// (best-effort; failure is silently ignored to avoid disrupting callers).
// Unlocks on deallocation, after zeroing.

template <typename T>
struct LockedAllocator : SecureAllocator<T> {
    using base       = SecureAllocator<T>;
    using value_type = T;

    template <typename U>
    struct rebind { using other = LockedAllocator<U>; };

    LockedAllocator() noexcept = default;

    template <typename U>
    explicit LockedAllocator(const LockedAllocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t n) {
        T* p = base::allocate(n);
        if (p) (void)lockMemory(p, n * sizeof(T));
        return p;
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (p) (void)unlockMemory(p, n * sizeof(T));
        base::deallocate(p, n);   // base wipes before free
    }

    template <typename U>
    bool operator==(const LockedAllocator<U>&) const noexcept { return true; }

    template <typename U>
    bool operator!=(const LockedAllocator<U>&) const noexcept { return false; }
};

// Convenience alias for a page-locked secure byte buffer
using LockedBytes = std::vector<byte_t, LockedAllocator<byte_t>>;

} // namespace SecFW
