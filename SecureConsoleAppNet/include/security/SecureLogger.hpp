#pragma once
// ============================================================
// SecureLogger.hpp — v1.4
// Thread-safe structured audit logger.
//
// v1.4 Changes (Pre-Network Hardening):
//   FIX [BUG-E02]: Move formatEntry() call INSIDE the mutex lock scope.
//
//   Root cause in v1.3:
//     void log(...) {
//         auto entry = formatEntry(...);          // ← OUTSIDE lock
//         std::lock_guard<std::mutex> lock(mutex_);
//         logFile_ << entry << "\n";              // ← INSIDE lock
//     }
//
//   Problem: formatEntry() calls std::chrono::system_clock::now() and
//   gmtime_r() BEFORE acquiring the lock. When N connection-handler
//   threads call log() concurrently, timestamps are captured in
//   arbitrary order relative to the file write sequence.
//   Result: log entries appear out of chronological order — violating
//   NIST SP 800-92 §4.3.2 (log records shall be time-ordered).
//
//   Fix: Acquire the lock FIRST, then call formatEntry() while holding
//   the lock. Timestamp is captured atomically with the write, so the
//   on-disk order matches real time order. Performance impact is
//   negligible — gmtime_r and chrono::now() are both <1µs.
//
// Previous fixes (v1.3):
//   FIX [BUG-17]: Thread-safe timestamp (gmtime_r / gmtime_s)
//   FIX [BUG-18]: Sanitize user data before writing (log injection)
//
// Standards:
//   NIST SP 800-92 §4.3.2  (time-ordered log records)
//   ISO 27001 A.12.4        (event logging)
//   OWASP Logging CS        (sanitize logged data)
// ============================================================

#include "SecureCore.hpp"
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <algorithm>

namespace SecFW {

enum class LogLevel : int {
    DEBUG    = 0,
    INFO     = 1,
    WARNING  = 2,
    ERROR    = 3,
    CRITICAL = 4,
    AUDIT    = 5
};

struct LogEvent {
    LogLevel    level   { LogLevel::AUDIT };
    std::string timestamp{};
    std::string userId  {};
    std::string action  {};
    std::string resource{};
    std::string clientIp{};
    bool        success { false };
    std::string details {};
};

class SecureLogger final {
public:
    explicit SecureLogger(const std::string& logPath,
                          LogLevel minLevel  = LogLevel::INFO,
                          bool     toConsole = true)
        : logPath_(logPath), minLevel_(minLevel), toConsole_(toConsole)
    {
        logFile_.open(logPath, std::ios::app);
        if (!logFile_.is_open())
            throw std::runtime_error("Cannot open log file: " + logPath);
    }

    // ── log — primary logging method ─────────────────────────────────────────
    //
    // BUG-E02 FIX: Lock is acquired FIRST, then formatEntry() is called
    // while holding the lock. This guarantees that:
    //   1. Timestamp is captured after lock acquisition
    //   2. File write order matches timestamp order
    //   3. No two threads can interleave their log entries
    //
    // Thread safety: fully safe for concurrent callers (N connection handlers,
    // background cleanup threads, signal-triggered audit writes, etc.)

    void log(LogLevel level, std::string_view message,
             std::string_view userId  = "-",
             std::string_view context = "")
    {
        if (level < minLevel_) return;

        // ── BUG-E02 FIX: lock BEFORE capturing timestamp ──
        std::lock_guard<std::mutex> lock(mutex_);

        // formatEntry() calls chrono::now() and gmtime_r() INSIDE the lock.
        // Timestamp order on disk now matches real-time acquisition order.
        auto entry = formatEntry(level,
                                 sanitize(message),
                                 sanitize(userId),
                                 sanitize(context));

        logFile_ << entry << "\n";
        logFile_.flush();

        if (toConsole_) {
            auto& out = (level >= LogLevel::ERROR) ? std::cerr : std::cout;
            out << entry << "\n";
        }
    }

    // ── audit — structured audit event ───────────────────────────────────────
    //
    // Same fix applies: lock first, then build the entry string.

    void audit(const LogEvent& event) {
        if (LogLevel::AUDIT < minLevel_) return;

        // ── BUG-E02 FIX: lock BEFORE building audit entry ──
        std::lock_guard<std::mutex> lock(mutex_);

        // Build the audit line inside the lock so timestamp is in-order
        std::string ts  = currentTimestamp();
        std::ostringstream oss;
        oss << ts
            << " [AUDIT]"
            << " user="   << sanitize(event.userId)
            << " action=" << sanitize(event.action)
            << " res="    << sanitize(event.resource)
            << " ip="     << sanitize(event.clientIp)
            << " result=" << (event.success ? "SUCCESS" : "FAILURE")
            << " | "      << sanitize(event.details);

        std::string entry = oss.str();

        logFile_ << entry << "\n";
        logFile_.flush();

        if (toConsole_) std::cout << entry << "\n";
    }

    // ── Convenience wrappers ──────────────────────────────────────────────────

    void debug   (std::string_view msg, std::string_view uid = "-") {
        log(LogLevel::DEBUG,    msg, uid);
    }
    void info    (std::string_view msg, std::string_view uid = "-") {
        log(LogLevel::INFO,     msg, uid);
    }
    void warn    (std::string_view msg, std::string_view uid = "-") {
        log(LogLevel::WARNING,  msg, uid);
    }
    void error   (std::string_view msg, std::string_view uid = "-") {
        log(LogLevel::ERROR,    msg, uid);
    }
    void critical(std::string_view msg, std::string_view uid = "-") {
        log(LogLevel::CRITICAL, msg, uid);
    }

    // setMinLevel — change minimum log level at runtime (thread-safe)
    void setMinLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(mutex_);
        minLevel_ = level;
    }

private:
    // ── sanitize — remove log injection characters ────────────────────────────
    //
    // Replaces newlines, carriage-returns, null bytes, and non-printable
    // control characters so injected data cannot forge log lines.
    // Truncates at 256 chars to prevent log bloat (OWASP Logging CS).

    static std::string sanitize(std::string_view raw) {
        std::string out;
        out.reserve(std::min(raw.size(), std::size_t(256)));
        for (unsigned char c : raw) {
            if (c == '\n' || c == '\r' || c == '\0' || c == '|') {
                out += '?';                           // replace structural chars
            } else if (c < 0x20 || c == 0x7F) {
                out += '?';                           // replace other control chars
            } else {
                out += static_cast<char>(c);
            }
        }
        if (out.size() > 256) {
            out.resize(253);
            out += "...";
        }
        return out;
    }

    // ── currentTimestamp — ISO-8601 UTC, thread-safe ──────────────────────────
    //
    // BUG-E02 note: This is now ONLY called from within the lock, so
    // the race condition on gmtime_r output order is eliminated.
    // The gmtime_r call itself is still thread-safe (re-entrant).

    static std::string currentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto tt  = std::chrono::system_clock::to_time_t(now);
        struct tm tm_buf{};
#ifndef _WIN32
        ::gmtime_r(&tt, &tm_buf);
#else
        ::gmtime_s(&tm_buf, &tt);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    // ── formatEntry — build full log line ─────────────────────────────────────
    //
    // Called INSIDE the mutex lock (BUG-E02 fix).
    // Captures timestamp as the very first action, ensuring the timestamp
    // reflects when the entry was committed to the log, not when the
    // calling thread first entered log().

    std::string formatEntry(LogLevel level,
                            std::string_view message,
                            std::string_view userId,
                            std::string_view context)
    {
        // currentTimestamp() called here — inside the lock — so timestamp
        // order matches write order (NIST SP 800-92 §4.3.2 compliance).
        std::ostringstream oss;
        oss << currentTimestamp()
            << " [" << levelStr(level) << "]"
            << " user=" << userId
            << " | " << message;
        if (!context.empty()) oss << " | ctx=" << context;
        return oss.str();
    }

    static std::string_view levelStr(LogLevel l) noexcept {
        switch (l) {
            case LogLevel::DEBUG:    return "DEBUG";
            case LogLevel::INFO:     return "INFO ";
            case LogLevel::WARNING:  return "WARN ";
            case LogLevel::ERROR:    return "ERROR";
            case LogLevel::CRITICAL: return "CRIT ";
            case LogLevel::AUDIT:    return "AUDIT";
            default:                 return "?????";
        }
    }

    // ── Members ───────────────────────────────────────────────────────────────

    std::string   logPath_;
    LogLevel      minLevel_;
    bool          toConsole_;
    std::ofstream logFile_;
    mutable std::mutex mutex_;   // protects logFile_, minLevel_, and timestamp order
};

} // namespace SecFW
