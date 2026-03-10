#pragma once
// ============================================================
// AuthManager.hpp — FIXED v1.3
// FIX [BUG-16]: cleanup() now removes ALL expired/stale entries,
//               not just locked ones — prevents memory leak
// Standards: OWASP Authentication CS, NIST SP 800-63B
// ============================================================
#include "SecureCore.hpp"
#include "SecureLogger.hpp"
#include <chrono>
#include <thread>
#include <unordered_map>
#include <atomic>
#include <mutex>

namespace SecFW {

struct SessionToken {
    std::string tokenId;
    std::string userId;
    u32_t       roleFlags    { 0 };
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

// ============================================================
// RateLimiter: Brute-force prevention (NIST SP 800-63B §5.2.2)
// ============================================================
class RateLimiter final {
public:
    // FIX: Add windowDuration param — entries older than this are always cleaned up
    explicit RateLimiter(u32_t maxAttempts = 5,
                         std::chrono::seconds lockoutDuration  = std::chrono::seconds(300),
                         std::chrono::seconds attemptWindow    = std::chrono::seconds(600))
        : maxAttempts_(maxAttempts)
        , lockoutDuration_(lockoutDuration)
        , attemptWindow_(attemptWindow) {}

    [[nodiscard]] bool isBlocked(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanup();
        auto now = std::chrono::system_clock::now();
        auto it = attempts_.find(key);
        if (it == attempts_.end()) return false;
        if (it->second.count < maxAttempts_) return false;
        if (now > it->second.lockedUntil) {
            attempts_.erase(it);
            return false;
        }
        return true;
    }

    void recordFailure(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanup();
        auto now = std::chrono::system_clock::now();
        auto& rec = attempts_[key];
        if (rec.firstAttempt == std::chrono::system_clock::time_point{})
            rec.firstAttempt = now;
        rec.count++;
        if (rec.count >= maxAttempts_)
            rec.lockedUntil = now + lockoutDuration_;
    }

    void reset(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        attempts_.erase(key);
    }

    [[nodiscard]] std::chrono::seconds remainingLockout(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanup();
        auto it = attempts_.find(key);
        if (it == attempts_.end()) return std::chrono::seconds(0);
        auto now = std::chrono::system_clock::now();
        if (now >= it->second.lockedUntil) return std::chrono::seconds(0);
        return std::chrono::duration_cast<std::chrono::seconds>(it->second.lockedUntil - now);
    }

    [[nodiscard]] std::size_t trackedCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return attempts_.size();
    }

private:
    // FIX [BUG-16]: Remove ALL stale entries — not just locked+expired ones
    // An entry is stale if:
    //   (a) lockout has expired, OR
    //   (b) attempt window has passed (even if never fully locked)
    void cleanup() {
        auto now = std::chrono::system_clock::now();
        for (auto it = attempts_.begin(); it != attempts_.end();) {
            bool lockoutExpired  = (it->second.count >= maxAttempts_) &&
                                   (now > it->second.lockedUntil);
            bool windowExpired   = (it->second.firstAttempt != std::chrono::system_clock::time_point{}) &&
                                   (now - it->second.firstAttempt > attemptWindow_);
            if (lockoutExpired || windowExpired)
                it = attempts_.erase(it);
            else
                ++it;
        }
    }

    struct AttemptRecord {
        u32_t count { 0 };
        std::chrono::system_clock::time_point lockedUntil{};
        std::chrono::system_clock::time_point firstAttempt{};
    };

    u32_t                maxAttempts_;
    std::chrono::seconds lockoutDuration_;
    std::chrono::seconds attemptWindow_;
    mutable std::mutex   mutex_;
    std::unordered_map<std::string, AttemptRecord> attempts_;
};

} // namespace SecFW
