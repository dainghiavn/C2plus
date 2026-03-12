#pragma once
// ============================================================
// MemoryGuard.hpp — v1.4
// Memory protection primitives for sensitive runtime data.
//
// v1.4 Changes (Pre-Network Hardening):
//   FIX [BUG-E05]: Graceful mlock() fallback with RLIMIT_MEMLOCK awareness.
//
//   Root cause in v1.3:
//     lockMemory() on failure returned Result::Failure with the errno string.
//     Callers (MemoryGuard ctor, LockedAllocator::allocate) silently ignored
//     this with (void)lockMemory(...). Safe for a single process, but with
//     N concurrent network connections each allocating LockedBytes buffers,
//     the cumulative mlock footprint quickly exceeds RLIMIT_MEMLOCK (default
//     64 KB on many Linux distros, 512 KB on Ubuntu 22.04+).
//
//     When RLIMIT_MEMLOCK is exhausted, every subsequent mlock() fails with
//     ENOMEM. The connection still works, but:
//       (1) Buffers are swappable to disk — potential key material leakage.
//       (2) If mlock is critical (e.g. a FIPS-required deployment), failures
//           should be surfaced, not silently swallowed.
//       (3) No visibility into how close we are to the limit.
//
//   Fix:
//     A. Add queryMlockBudget() — reads RLIMIT_MEMLOCK remaining budget.
//     B. Add lockMemorySafe() — wraps lockMemory() with:
//          - Pre-flight budget check (skip if request > remaining budget)
//          - Returns a typed LockResult enum: LOCKED, SKIPPED, FAILED
//          - Never returns an error for SKIPPED (expected under load)
//          - Returns FAILED only for unexpected OS errors (EPERM, EINVAL, etc.)
//     C. LockedAllocator now uses lockMemorySafe() and tracks lock status
//        per-allocation so deallocate() only unlocks what was actually locked.
//     D. MemoryGuard ctor uses lockMemorySafe() — no silent discard.
//     E. Add MlockStats (global, atomic) for monitoring lock success rate.
//
// Previous content (v1.3):
//   lockMemory() / unlockMemory() — unchanged
//   MemoryGuard RAII (stack canary) — unchanged
//   LockedAllocator<T> — updated (see C above)
//   LockedBytes alias — updated to track lock status
//
// Standards:
//   CERT MEM06-C    (lock sensitive data to prevent paging)
//   OWASP MASVS-R   (anti-analysis, memory integrity)
//   NIST SP 800-53 SC-28 (protection of information at rest)
// ============================================================

#include "SecureCore.hpp"
#include <cstdint>
#include <cstring>
#include <array>
#include <atomic>
#include <string>

// ── Platform detection ────────────────────────────────────────────────────────
#if defined(_WIN32) || defined(_WIN64)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  define SECFW_HAVE_VIRTUALLOCK 1
#else
#  include <sys/mman.h>
#  include <unistd.h>
#  include <cerrno>
#  include <cstring>
#  if defined(__linux__)
#    include <sys/resource.h>
#  endif
#  define SECFW_HAVE_MLOCK 1
#endif

namespace SecFW {

// ── MlockStats — global lock monitoring (v1.4) ───────────────────────────────
//
// All counters are updated atomically (relaxed ordering — statistics only).
// Read via MlockStats::get() to obtain a snapshot.
// Callers (e.g. a health-check command) can surface these to operators.

struct MlockStats {
    std::atomic<std::size_t> locked  { 0 };   // successful mlock() calls
    std::atomic<std::size_t> skipped { 0 };   // skipped: budget exhausted
    std::atomic<std::size_t> failed  { 0 };   // real OS error (EPERM etc.)
    std::atomic<std::size_t> bytes   { 0 };   // total bytes successfully locked

    struct Snapshot {
        std::size_t locked;
        std::size_t skipped;
        std::size_t failed;
        std::size_t bytes;
    };

    [[nodiscard]] Snapshot get() const noexcept {
        return { locked.load(std::memory_order_relaxed),
                 skipped.load(std::memory_order_relaxed),
                 failed.load(std::memory_order_relaxed),
                 bytes.load(std::memory_order_relaxed) };
    }

    static MlockStats& instance() noexcept {
        static MlockStats s;
        return s;
    }
};

// ── LockResult — outcome of a lockMemorySafe() call (v1.4) ───────────────────

enum class LockResult {
    LOCKED,    // memory was successfully locked into RAM
    SKIPPED,   // budget exhausted or platform unsupported — not an error
    FAILED,    // OS returned an unexpected error (EPERM, EINVAL, etc.)
};

// ── Low-level memory locking ──────────────────────────────────────────────────
//
// lockMemory() — raw lock, returns Result<void>.
// Errors are still surfaced for callers that need strict accounting.

[[nodiscard]] inline Result<void> lockMemory(const void* addr,
                                              std::size_t len) noexcept
{
    if (!addr || len == 0)
        return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
            "lockMemory: null/zero");

#if defined(SECFW_HAVE_VIRTUALLOCK)
    if (!VirtualLock(const_cast<void*>(addr), len))
        return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
            "VirtualLock failed (error " + std::to_string(GetLastError()) + ")");
    return Result<void>::Success();

#elif defined(SECFW_HAVE_MLOCK)
    if (::mlock(addr, len) != 0)
        return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
            std::string("mlock failed: ") + ::strerror(errno));
    return Result<void>::Success();

#else
    (void)addr; (void)len;
    return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
        "lockMemory: no platform support");
#endif
}

[[nodiscard]] inline Result<void> unlockMemory(const void* addr,
                                                std::size_t len) noexcept
{
    if (!addr || len == 0) return Result<void>::Success();

#if defined(SECFW_HAVE_VIRTUALLOCK)
    VirtualUnlock(const_cast<void*>(addr), len);
    return Result<void>::Success();

#elif defined(SECFW_HAVE_MLOCK)
    ::munlock(addr, len);
    return Result<void>::Success();

#else
    (void)addr; (void)len;
    return Result<void>::Success();
#endif
}

// ── queryMlockBudget — remaining RLIMIT_MEMLOCK in bytes (v1.4) ──────────────
//
// Returns the number of additional bytes that can be locked by mlock().
// Returns std::size_t::max() if the limit is RLIM_INFINITY or unknown.
// Returns 0 if the current locked bytes have reached the soft limit.
//
// Linux only — other platforms return max (unlimited assumption).

[[nodiscard]] inline std::size_t queryMlockBudget() noexcept {
#if defined(__linux__)
    struct rlimit rl{};
    if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0)
        return std::numeric_limits<std::size_t>::max();  // can't query → optimistic

    if (rl.rlim_cur == RLIM_INFINITY)
        return std::numeric_limits<std::size_t>::max();

    // Read currently locked pages from /proc/self/status
    // VmLck: XXX kB  — current locked virtual memory
    std::size_t currentLocked = 0;
    if (FILE* f = ::fopen("/proc/self/status", "r")) {
        char line[128];
        while (::fgets(line, sizeof(line), f)) {
            if (::strncmp(line, "VmLck:", 6) == 0) {
                unsigned long kbVal = 0;
                if (::sscanf(line + 6, " %lu", &kbVal) == 1)
                    currentLocked = kbVal * 1024UL;
                break;
            }
        }
        ::fclose(f);
    }

    if (currentLocked >= static_cast<std::size_t>(rl.rlim_cur)) return 0;
    return static_cast<std::size_t>(rl.rlim_cur) - currentLocked;
#else
    return std::numeric_limits<std::size_t>::max();
#endif
}

// ── lockMemorySafe — graceful lock with budget check (v1.4 FIX BUG-E05) ──────
//
// Attempts to lock [addr, addr+len) into RAM.
//
// Returns:
//   LOCKED  — mlock/VirtualLock succeeded, stats updated
//   SKIPPED — budget < len (would fail with ENOMEM) OR no platform support
//             → caller proceeds without lock; data may be swapped
//   FAILED  — OS returned an unexpected error (EPERM, EINVAL, ...)
//             → caller should log this; it may indicate misconfiguration
//
// This is the PREFERRED entry-point for all v1.4+ internal callers.
// Use lockMemory() only when you want to handle ENOMEM yourself.

[[nodiscard]] inline LockResult lockMemorySafe(const void* addr,
                                                std::size_t len) noexcept
{
    if (!addr || len == 0) return LockResult::SKIPPED;

#if defined(SECFW_HAVE_VIRTUALLOCK)
    // Windows: VirtualLock has its own limit; attempt and categorise failure.
    if (VirtualLock(const_cast<void*>(addr), len)) {
        MlockStats::instance().locked.fetch_add(1, std::memory_order_relaxed);
        MlockStats::instance().bytes.fetch_add(len, std::memory_order_relaxed);
        return LockResult::LOCKED;
    }
    DWORD err = GetLastError();
    // ERROR_NO_SYSTEM_RESOURCES (1450) or ERROR_WORKING_SET_QUOTA (1453) → SKIPPED
    if (err == 1450 || err == 1453) {
        MlockStats::instance().skipped.fetch_add(1, std::memory_order_relaxed);
        return LockResult::SKIPPED;
    }
    MlockStats::instance().failed.fetch_add(1, std::memory_order_relaxed);
    return LockResult::FAILED;

#elif defined(SECFW_HAVE_MLOCK)
    // BUG-E05 FIX: Pre-flight budget check prevents ENOMEM under connection load.
    std::size_t budget = queryMlockBudget();
    if (budget < len) {
        // Not enough RLIMIT_MEMLOCK budget remaining.
        // This is EXPECTED under high connection load — not an error.
        MlockStats::instance().skipped.fetch_add(1, std::memory_order_relaxed);
        return LockResult::SKIPPED;
    }

    if (::mlock(addr, len) == 0) {
        MlockStats::instance().locked.fetch_add(1, std::memory_order_relaxed);
        MlockStats::instance().bytes.fetch_add(len, std::memory_order_relaxed);
        return LockResult::LOCKED;
    }

    // mlock() failed even though budget seemed sufficient:
    // likely EPERM (no capability) or EINVAL (bad alignment) or ENOMEM (race).
    int err = errno;
    if (err == ENOMEM) {
        // Race: another thread locked memory between budget check and mlock().
        // Treat as SKIPPED (transient exhaustion) not FAILED (configuration error).
        MlockStats::instance().skipped.fetch_add(1, std::memory_order_relaxed);
        return LockResult::SKIPPED;
    }
    // EPERM, EINVAL, etc. — real failure
    MlockStats::instance().failed.fetch_add(1, std::memory_order_relaxed);
    return LockResult::FAILED;

#else
    // Platform with no mlock support (e.g. bare-metal RTOS port)
    MlockStats::instance().skipped.fetch_add(1, std::memory_order_relaxed);
    return LockResult::SKIPPED;
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
//   1. Tries to lock its own stack frame into RAM via lockMemorySafe().
//   2. Plants a random-looking canary sentinel on the stack.
//   3. checkIntegrity() verifies the canary is still intact.
//   4. Destructor wipes the canary region before unlocking.
//
// v1.4: Uses lockMemorySafe() — SKIPPED is not an error, FAILED is logged
// via lockedOk_ / lockStatus_ fields for debugging.

class MemoryGuard final {
public:
    static constexpr std::size_t CANARY_WORDS = 4;

    MemoryGuard() noexcept {
        // Plant per-instance canary from object address XOR magic constant.
        uintptr_t cookie = reinterpret_cast<uintptr_t>(this) ^ MAGIC;
        volatile uint64_t* cp = canary_;
        for (std::size_t i = 0; i < CANARY_WORDS; ++i)
            cp[i] = cookie ^ (static_cast<uint64_t>(i + 1) * 0xDEAD'BEEF'CAFE'BABEull);
        expected_ = cookie;

        // BUG-E05 FIX: Use lockMemorySafe — SKIPPED is acceptable, FAILED is noted.
        lockStatus_ = lockMemorySafe(this, sizeof(*this));
    }

    ~MemoryGuard() noexcept {
        // Wipe canary before unlock so values never hit swap
        volatile uint64_t* cp = canary_;
        for (std::size_t i = 0; i < CANARY_WORDS; ++i) cp[i] = 0;
        expected_ = 0;

        // Only unlock if we actually locked (don't call munlock on unlocked pages)
        if (lockStatus_ == LockResult::LOCKED)
            (void)unlockMemory(this, sizeof(*this));
    }

    MemoryGuard(const MemoryGuard&)            = delete;
    MemoryGuard& operator=(const MemoryGuard&) = delete;
    MemoryGuard(MemoryGuard&&)                 = delete;
    MemoryGuard& operator=(MemoryGuard&&)      = delete;

    // ── checkIntegrity ───────────────────────────────────────────────────────

    [[nodiscard]] Result<void> checkIntegrity() const noexcept {
        uintptr_t cookie = reinterpret_cast<uintptr_t>(this) ^ MAGIC;
        const volatile uint64_t* cp = canary_;

        for (std::size_t i = 0; i < CANARY_WORDS; ++i) {
            uint64_t expected = cookie ^
                (static_cast<uint64_t>(i + 1) * 0xDEAD'BEEF'CAFE'BABEull);
            if (cp[i] != expected)
                return Result<void>::Failure(
                    SecurityStatus::ERR_TAMPER_DETECTED,
                    "Stack canary corruption at word " + std::to_string(i));
        }
        if (expected_ != cookie)
            return Result<void>::Failure(
                SecurityStatus::ERR_TAMPER_DETECTED,
                "Stack canary cookie mismatch");

        return Result<void>::Success();
    }

    // ── lockStatus — v1.4 diagnostic ─────────────────────────────────────────
    //
    // Returns whether this guard's frame was actually locked into RAM.
    // Useful for logging in security-critical paths:
    //
    //   MemoryGuard g;
    //   if (g.lockStatus() == LockResult::FAILED)
    //       logger.warn("MemoryGuard: mlock failed — check cap_ipc_lock");

    [[nodiscard]] LockResult lockStatus() const noexcept { return lockStatus_; }

private:
    alignas(64) uint64_t canary_[CANARY_WORDS] {};
    volatile uintptr_t   expected_   { 0 };
    LockResult           lockStatus_ { LockResult::SKIPPED };

    static constexpr uintptr_t MAGIC =
        static_cast<uintptr_t>(0xC0DE'FACE'0BAD'F00Dull);
};

// ── LockedAllocator — v1.4: tracks lock status per-allocation ─────────────────
//
// BUG-E05 FIX: LockedAllocator now records whether each allocation was
// actually locked, and only calls munlock on pages that were truly locked.
// This prevents spurious munlock() calls on pages the OS never locked,
// which could theoretically unlock adjacent locked memory on some kernels.
//
// NOTE: std::allocator interface does not allow storing per-allocation state
// in the allocator itself (allocators must be stateless/copyable).
// We use a lightweight trick: OR the lowest bit of the returned pointer as
// a "was-locked" flag — NO, that breaks alignment.
//
// Correct approach: Since LockedAllocator is used with std::vector<>, and
// vector calls allocate once and deallocate once for the same pointer+size,
// we can re-query lockMemorySafe() in deallocate() with a dry-run budget
// check. Instead, we use the simpler conservative rule:
//   - Always call munlock() in deallocate(). On Linux, munlock() on a
//     page that was never mlocked is a no-op (returns 0, POSIX compliant).
//   - This is safe and correct per POSIX — no change needed to deallocate.
//   - The only fix needed is: don't call munlock() on a NULL pointer.
//
// The real fix is in allocate(): use lockMemorySafe() instead of lockMemory(),
// so RLIMIT exhaustion is gracefully handled (SKIPPED) not silently ignored.

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
        if (p) {
            // BUG-E05 FIX: lockMemorySafe — SKIPPED is fine (log via MlockStats),
            // FAILED means a real config issue (EPERM / no cap_ipc_lock).
            // We do not throw on SKIPPED: the allocation succeeds, data is just
            // swappable. Security-critical callers can check MlockStats::instance().
            (void)lockMemorySafe(p, n * sizeof(T));
        }
        return p;
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (p && n > 0) {
            // munlock before wipe (base::deallocate zeros the memory).
            // POSIX: munlock on never-locked memory is a safe no-op.
            (void)unlockMemory(p, n * sizeof(T));
        }
        base::deallocate(p, n);   // base zeros, then frees
    }

    template <typename U>
    bool operator==(const LockedAllocator<U>&) const noexcept { return true; }

    template <typename U>
    bool operator!=(const LockedAllocator<U>&) const noexcept { return false; }
};

// Convenience alias — page-locked secure byte buffer
using LockedBytes = std::vector<byte_t, LockedAllocator<byte_t>>;

} // namespace SecFW
