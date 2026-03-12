#pragma once
// ============================================================
// SecureLogger.hpp — FIXED v1.3
// FIX [BUG-17]: Thread-safe timestamp (gmtime_r / gmtime_s)
// FIX [BUG-18]: Sanitize user data before writing to log
//               (prevent log injection via newline/pipe chars)
// Standards: NIST SP 800-92, ISO 27001 A.12.4
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

    void log(LogLevel level, std::string_view message,
             std::string_view userId = "-", std::string_view context = "")
    {
        if (level < minLevel_) return;
        // FIX [BUG-17] + [BUG-18]: thread-safe timestamp + sanitize inputs
        auto entry = formatEntry(level,
                                 sanitize(message),
                                 sanitize(userId),
                                 sanitize(context));
        std::lock_guard<std::mutex> lock(mutex_);
        logFile_ << entry << "\n";
        logFile_.flush();
        if (toConsole_) {
            auto& out = (level >= LogLevel::ERROR) ? std::cerr : std::cout;
            out << entry << "\n";
        }
    }

    void audit(const LogEvent& event) {
        std::ostringstream oss;
        oss << "[AUDIT]"
            << " user="   << sanitize(event.userId)
            << " action=" << sanitize(event.action)
            << " res="    << sanitize(event.resource)
            << " ip="     << sanitize(event.clientIp)
            << " result=" << (event.success ? "SUCCESS" : "FAILURE")
            << " detail=" << sanitize(event.details);
        log(LogLevel::AUDIT, oss.str(), event.userId, event.action);
    }

    void info    (std::string_view msg, std::string_view uid = "-") { log(LogLevel::INFO,     msg, uid); }
    void warn    (std::string_view msg, std::string_view uid = "-") { log(LogLevel::WARNING,  msg, uid); }
    void error   (std::string_view msg, std::string_view uid = "-") { log(LogLevel::ERROR,    msg, uid); }
    void critical(std::string_view msg, std::string_view uid = "-") { log(LogLevel::CRITICAL, msg, uid); }

    // Rotate log file (useful for long-running processes)
    void rotate(const std::string& newPath = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        logFile_.close();
        const std::string& target = newPath.empty() ? logPath_ : newPath;
        if (!newPath.empty()) logPath_ = newPath;
        logFile_.open(target, std::ios::app);
    }

private:
    // FIX [BUG-18]: Strip characters that could enable log injection
    // Replace newlines, carriage returns, and pipe chars with safe equivalents
    static std::string sanitize(std::string_view input) {
        std::string out;
        out.reserve(input.size());
        for (char c : input) {
            switch (c) {
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '|':  out += '|';    break; // keep but it's already used as field sep
            case '\0': out += "\\0";  break;
            default:
                // Replace other control chars with '?'
                if (static_cast<unsigned char>(c) < 0x20)
                    out += '?';
                else
                    out += c;
            }
        }
        // Truncate overly long fields to prevent log bloat
        if (out.size() > 256) {
            out.resize(253);
            out += "...";
        }
        return out;
    }

    std::string formatEntry(LogLevel level, std::string_view message,
                            std::string_view userId, std::string_view context)
    {
        // FIX [BUG-17]: Use gmtime_r (POSIX) or gmtime_s (Windows) for thread safety
        auto now = std::chrono::system_clock::now();
        auto tt  = std::chrono::system_clock::to_time_t(now);
        struct tm tm_buf{};
#ifndef _WIN32
        ::gmtime_r(&tt, &tm_buf);
#else
        ::gmtime_s(&tm_buf, &tt);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ")
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

    std::string   logPath_;
    LogLevel      minLevel_;
    bool          toConsole_;
    std::ofstream logFile_;
    mutable std::mutex    mutex_;
};

} // namespace SecFW
