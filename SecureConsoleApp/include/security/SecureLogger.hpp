#pragma once
// ============================================================
// SecureLogger.hpp
// Standards: NIST SP 800-92, ISO 27001 A.12.4
// ============================================================
#include "SecureCore.hpp"
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>

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
        auto entry = formatEntry(level, message, userId, context);
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
            << " user="   << event.userId
            << " action=" << event.action
            << " res="    << event.resource
            << " ip="     << event.clientIp
            << " result=" << (event.success ? "SUCCESS" : "FAILURE")
            << " detail=" << event.details;
        log(LogLevel::AUDIT, oss.str(), event.userId, event.action);
    }

    void info    (std::string_view msg, std::string_view uid = "-") { log(LogLevel::INFO,     msg, uid); }
    void warn    (std::string_view msg, std::string_view uid = "-") { log(LogLevel::WARNING,  msg, uid); }
    void error   (std::string_view msg, std::string_view uid = "-") { log(LogLevel::ERROR,    msg, uid); }
    void critical(std::string_view msg, std::string_view uid = "-") { log(LogLevel::CRITICAL, msg, uid); }

private:
    std::string formatEntry(LogLevel level, std::string_view message,
                            std::string_view userId, std::string_view context)
    {
        auto now = std::chrono::system_clock::now();
        auto tt  = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%SZ")
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
    std::mutex    mutex_;
};

} // namespace SecFW
