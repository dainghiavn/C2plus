#pragma once
// ============================================================
// AuthManager.hpp — FIXED: RateLimiter cleanup old entries
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
};

// ============================================================
// RateLimiter: Brute-force prevention (NIST SP 800-63B §5.2.2)
// ============================================================
class RateLimiter final {
public:
    explicit RateLimiter(u32_t maxAttempts = 5,
                         std::chrono::seconds lockoutDuration = std::chrono::seconds(300))
        : maxAttempts_(maxAttempts), lockoutDuration_(lockoutDuration) {}

    [[nodiscard]] bool isBlocked(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanup(); // remove expired entries
        auto now = std::chrono::system_clock::now();
        auto it = attempts_.find(key);
        if (it == attempts_.end()) return false;
        if (now > it->second.lockedUntil) { attempts_.erase(it); return false; }
        return it->second.count >= maxAttempts_;
    }

    void recordFailure(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanup();
        auto& rec = attempts_[key];
        rec.count++;
        if (rec.count >= maxAttempts_)
            rec.lockedUntil = std::chrono::system_clock::now() + lockoutDuration_;
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
        auto remaining = it->second.lockedUntil - std::chrono::system_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(remaining);
    }

private:
    void cleanup() {
        auto now = std::chrono::system_clock::now();
        for (auto it = attempts_.begin(); it != attempts_.end();) {
            if (now > it->second.lockedUntil && it->second.count >= maxAttempts_)
                it = attempts_.erase(it);
            else
                ++it;
        }
    }

    struct AttemptRecord {
        u32_t count { 0 };
        std::chrono::system_clock::time_point lockedUntil{};
    };
    u32_t                maxAttempts_;
    std::chrono::seconds lockoutDuration_;
    std::mutex           mutex_;
    std::unordered_map<std::string, AttemptRecord> attempts_;
};

} // namespace SecFW
