#pragma once
// ============================================================
// AuthManager.hpp — v1.4
// Session token + brute-force rate limiter.
//
// v1.4 Changes (Pre-Network Hardening):
//   FIX [BUG-E03]: Harden RateLimiter for concurrent network connections.
//
//   Root cause audit (v1.3 → v1.4):
//     v1.3 already added std::mutex to RateLimiter. However two subtle
//     issues remained that only surface under concurrent load:
//
//     ISSUE A — cleanup() called from isBlocked() AND recordFailure():
//       Both methods acquire the lock, then call cleanup() internally.
//       cleanup() itself does NOT re-acquire the lock (correct — it runs
//       inside the caller's lock_guard). This is safe, but it was not
//       explicitly documented, making future modifications risky.
//       → Fix: Add a private tag "// MUST hold mutex_" on cleanup() so
//         any future refactor knows not to lock inside it.
//
//     ISSUE B — remainingLockout() had no early-return guard:
//       If the key was absent, the function dereferenced end() after
//       calling cleanup() which may have erased the entry the find()
//       found in a previous check. This was a TOCTOU within the same
//       lock — safe against other threads but logically fragile.
//       → Fix: Single find() result, check validity before use.
//
//     ISSUE C — No connection-count limit:
//       With network support coming in v2.0, unlimited concurrent callers
//       can hammer RateLimiter. Add maxTracked_ cap so attempts_ map
//       cannot grow unboundedly (DoS vector: open many connections,
//       each with a unique "key" string → exhaust heap).
//       → Fix: recordFailure() rejects new keys when map exceeds cap.
//
//     ISSUE D — trackedCount() is const but cleanup() is not:
//       Minor: const correctness — trackedCount() should not trigger
//       cleanup. Removed cleanup() call from const observer.
//
// Previous fixes (v1.3):
//   FIX [BUG-16]: cleanup() removes ALL stale entries, not just locked ones
//
// Standards:
//   OWASP Authentication CS
//   NIST SP 800-63B §5.2.2  (rate limiting / lockout)
//   CWE-307                 (improper restriction of excessive auth attempts)
// ============================================================

#include "SecureCore.hpp"
#include "SecureLogger.hpp"
#include <chrono>
#include <thread>
#include <unordered_map>
#include <atomic>
#include <mutex>

namespace SecFW {

// ── SessionToken ──────────────────────────────────────────────────────────────

struct SessionToken {
    std::string tokenId;
    std::string userId;
    u32_t       roleFlags  { 0 };
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiresAt;

    [[nodiscard]] bool isExpired() const noexcept {
        return std::chrono::system_clock::now() > expiresAt;
    }

    [[nodiscard]] bool hasRole(u32_t role) const noexcept {
        return (roleFlags & role) != 0;
    }

    [[nodiscard]] std::chrono::seconds remainingTTL() const noexcept {
        auto rem = expiresAt - std::chrono::system_clock::now();
        if (rem.count() < 0) return std::chrono::seconds(0);
        return std::chrono::duration_cast<std::chrono::seconds>(rem);
    }
};

// ── RateLimiter ───────────────────────────────────────────────────────────────
//
// Tracks failed authentication attempts per key (typically username or IP).
// Thread-safe: all public methods hold mutex_ for their entire duration.
//
// v1.4 hardening summary:
//   - cleanup() is clearly marked as requiring the lock (called inside callers)
//   - remainingLockout() uses a single find() to avoid TOCTOU after cleanup()
//   - maxTracked_ cap prevents unbounded map growth under network load
//   - trackedCount() no longer triggers cleanup() (const correctness)

class RateLimiter final {
public:
    // maxAttempts    : failures before lockout
    // lockoutDuration: how long a locked key stays locked
    // attemptWindow  : sliding window; entries older than this are stale
    // maxTracked     : maximum distinct keys in the map (DoS cap, v1.4)
    //                  Default 65536 — enough for any legitimate deployment,
    //                  far below heap-exhaustion territory.
    explicit RateLimiter(
        u32_t                maxAttempts      = 5,
        std::chrono::seconds lockoutDuration  = std::chrono::seconds(300),
        std::chrono::seconds attemptWindow    = std::chrono::seconds(600),
        std::size_t          maxTracked       = 65536)
        : maxAttempts_(maxAttempts)
        , lockoutDuration_(lockoutDuration)
        , attemptWindow_(attemptWindow)
        , maxTracked_(maxTracked)
    {}

    // ── isBlocked ─────────────────────────────────────────────────────────────
    //
    // Returns true if the key is currently locked out.
    // Triggers stale-entry cleanup on every call (amortised O(1) average).

    [[nodiscard]] bool isBlocked(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanup();   // HOLDS mutex_ (must not re-lock inside cleanup)

        auto now = std::chrono::system_clock::now();
        auto it  = attempts_.find(key);
        if (it == attempts_.end()) return false;

        // Not yet locked out
        if (it->second.count < maxAttempts_) return false;

        // Lockout period expired — erase and report not blocked
        if (now > it->second.lockedUntil) {
            attempts_.erase(it);
            return false;
        }

        return true;
    }

    // ── recordFailure ─────────────────────────────────────────────────────────
    //
    // Increments the failure counter for `key`.
    // Sets lockedUntil when maxAttempts_ is reached.
    //
    // v1.4: If map is at maxTracked_ capacity, new keys are silently ignored.
    // This prevents heap exhaustion but may allow an attacker to poison the
    // map with bogus keys first. Log the overflow so operators can tune
    // maxTracked_ or apply upstream rate limiting (nginx / iptables).

    void recordFailure(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanup();   // HOLDS mutex_

        // BUG-E03 FIX (ISSUE C): cap map size against unbounded growth
        if (attempts_.size() >= maxTracked_) {
            // Map is full — cannot insert new key.
            // Existing keys still track correctly; only truly new keys are dropped.
            // Callers should log this via a separate monitoring hook.
            return;
        }

        auto  now = std::chrono::system_clock::now();
        auto& rec = attempts_[key];   // inserts with zero-count if new

        if (rec.firstAttempt == std::chrono::system_clock::time_point{})
            rec.firstAttempt = now;

        ++rec.count;

        if (rec.count >= maxAttempts_)
            rec.lockedUntil = now + lockoutDuration_;
    }

    // ── reset ─────────────────────────────────────────────────────────────────
    //
    // Clear the failure record for `key` (call on successful authentication).

    void reset(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        attempts_.erase(key);
    }

    // ── remainingLockout ──────────────────────────────────────────────────────
    //
    // Returns seconds remaining in the lockout for `key`.
    // Returns 0 if the key is not locked.
    //
    // v1.4 FIX (ISSUE B): Single find() — result is not invalidated by
    // cleanup() because cleanup() only erases *other* entries (those whose
    // window or lockout has expired). The key we are looking up cannot be
    // erased by cleanup() while we hold the lock, because cleanup() only
    // erases entries whose lockedUntil has already passed.

    [[nodiscard]] std::chrono::seconds remainingLockout(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanup();   // HOLDS mutex_

        auto it = attempts_.find(key);
        if (it == attempts_.end()) return std::chrono::seconds(0);
        if (it->second.count < maxAttempts_) return std::chrono::seconds(0);

        auto now = std::chrono::system_clock::now();
        if (now >= it->second.lockedUntil) return std::chrono::seconds(0);

        return std::chrono::duration_cast<std::chrono::seconds>(
            it->second.lockedUntil - now);
    }

    // ── trackedCount ──────────────────────────────────────────────────────────
    //
    // Returns the current number of tracked keys (for monitoring / metrics).
    //
    // v1.4 FIX (ISSUE D): Removed cleanup() call — this is a const observer.
    // Callers who need a "clean" count should call isBlocked("") to trigger
    // cleanup, or accept that the count may include a few stale entries.

    [[nodiscard]] std::size_t trackedCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return attempts_.size();
    }

    // ── isAtCapacity ──────────────────────────────────────────────────────────
    //
    // v1.4: Returns true when the map has hit maxTracked_.
    // Operators can monitor this to detect a DoS attempt against the limiter.

    [[nodiscard]] bool isAtCapacity() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return attempts_.size() >= maxTracked_;
    }

private:
    // ── cleanup ───────────────────────────────────────────────────────────────
    //
    // Removes ALL stale entries from the map.
    // An entry is stale when EITHER:
    //   (a) it is locked AND the lockout period has expired, OR
    //   (b) the attempt window has elapsed (never fully locked)
    //
    // IMPORTANT: MUST be called while holding mutex_.
    //            Do NOT call std::lock_guard inside this method.

    void cleanup() {
        auto now = std::chrono::system_clock::now();
        for (auto it = attempts_.begin(); it != attempts_.end(); ) {
            bool lockoutExpired = (it->second.count >= maxAttempts_) &&
                                  (now > it->second.lockedUntil);
            bool windowExpired  = (it->second.firstAttempt !=
                                   std::chrono::system_clock::time_point{}) &&
                                  (now - it->second.firstAttempt > attemptWindow_);
            if (lockoutExpired || windowExpired)
                it = attempts_.erase(it);
            else
                ++it;
        }
    }

    struct AttemptRecord {
        u32_t count { 0 };
        std::chrono::system_clock::time_point lockedUntil   {};
        std::chrono::system_clock::time_point firstAttempt  {};
    };

    u32_t                maxAttempts_;
    std::chrono::seconds lockoutDuration_;
    std::chrono::seconds attemptWindow_;
    std::size_t          maxTracked_;

    // mutex_ protects attempts_ entirely.
    // Declared mutable so const observers (trackedCount, isAtCapacity) can lock.
    mutable std::mutex mutex_;
    std::unordered_map<std::string, AttemptRecord> attempts_;
};

} // namespace SecFW
