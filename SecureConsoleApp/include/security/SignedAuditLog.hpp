#pragma once
// ============================================================
// SignedAuditLog.hpp — NEW FEATURE v1.3
//
// Tamper-evident audit log using HMAC chain.
// Each log entry includes:
//   - Sequential entry ID
//   - HMAC-SHA256 of current entry + previous chain hash
// Any modification/deletion of a past entry breaks the chain.
//
// Verification:
//   SignedAuditLog::verify(logPath, key) → reports first tampered line
//
// Standards: NIST SP 800-92, PCI-DSS Requirement 10
// ============================================================
#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <filesystem>

namespace SecFW {

struct AuditEntry {
    u64_t       seqId    { 0 };
    std::string timestamp{};
    std::string userId   {};
    std::string action   {};
    std::string result   {};  // SUCCESS / FAILURE
    std::string details  {};
    std::string srcIp    {};
};

// ============================================================
// SignedAuditLog
// ============================================================
class SignedAuditLog final {
public:
    // logPath: where to write the chained log
    // hmacKey: 32-byte key for HMAC computation
    explicit SignedAuditLog(const std::string& logPath,
                             std::span<const byte_t> hmacKey)
        : logPath_(logPath)
        , hmacKey_(hmacKey.begin(), hmacKey.end())
    {
        // Load last chain hash from existing log (allows appending)
        lastChainHash_ = loadLastHash(logPath);

        file_.open(logPath, std::ios::app | std::ios::binary);
        if (!file_.is_open())
            throw std::runtime_error("Cannot open audit log: " + logPath);

        // Set file permissions (owner read/write only)
#ifndef _WIN32
        namespace fs = std::filesystem;
        if (fs::exists(logPath))
            fs::permissions(logPath,
                fs::perms::owner_read | fs::perms::owner_write,
                fs::perm_options::replace);
#endif
    }

    // ── Write an audit entry ──
    [[nodiscard]] Result<void> write(const AuditEntry& entry) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string timestamp = getTimestamp();
        u64_t seqId = ++seqCounter_;

        // Build the log line (without HMAC)
        std::ostringstream lineStream;
        lineStream << seqId << "|"
                   << timestamp << "|"
                   << sanitize(entry.userId) << "|"
                   << sanitize(entry.action) << "|"
                   << (entry.result.empty() ? "SUCCESS" : sanitize(entry.result)) << "|"
                   << sanitize(entry.details) << "|"
                   << sanitize(entry.srcIp);
        std::string lineData = lineStream.str();

        // HMAC = HMAC(lineData + prevHash, key)
        std::string chainInput = lineData + "|" + lastChainHash_;
        SecBytes chainInputBytes(chainInput.begin(), chainInput.end());
        auto hmacRes = CryptoEngine::computeHMAC(chainInputBytes, hmacKey_);
        if (hmacRes.fail())
            return Result<void>::Failure(hmacRes.status,
                "HMAC computation failed: " + hmacRes.message);

        std::string hmacHex = CryptoEngine::toHex(hmacRes.value);
        lastChainHash_ = hmacHex;

        // Final line: lineData|HMAC
        std::string finalLine = lineData + "|" + hmacHex + "\n";

        file_ << finalLine;
        file_.flush();

        if (!file_.good())
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Write to audit log failed");

        return Result<void>::Success();
    }

    // ── Convenience method ──
    Result<void> log(std::string_view userId, std::string_view action,
                     bool success = true, std::string_view details = "",
                     std::string_view srcIp = "-")
    {
        return write({
            .userId  = std::string(userId),
            .action  = std::string(action),
            .result  = success ? "SUCCESS" : "FAILURE",
            .details = std::string(details),
            .srcIp   = std::string(srcIp)
        });
    }

    // ── Verify integrity of an existing log file ──
    [[nodiscard]] static Result<void> verify(
        const std::string& logPath,
        std::span<const byte_t> hmacKey)
    {
        std::ifstream f(logPath);
        if (!f.is_open())
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Cannot open log for verification: " + logPath);

        std::string prevHash = "0000000000000000000000000000000000000000000000000000000000000000";
        std::string line;
        u64_t lineNum = 0;

        while (std::getline(f, line)) {
            ++lineNum;
            if (line.empty()) continue;

            // Find last pipe — HMAC is after it
            auto lastPipe = line.rfind('|');
            if (lastPipe == std::string::npos || lastPipe + 1 >= line.size())
                return Result<void>::Failure(SecurityStatus::ERR_TAMPER_DETECTED,
                    "Malformed line at #" + std::to_string(lineNum));

            std::string lineData = line.substr(0, lastPipe);
            std::string storedHmac = line.substr(lastPipe + 1);

            // Recompute HMAC
            std::string chainInput = lineData + "|" + prevHash;
            SecBytes chainInputBytes(chainInput.begin(), chainInput.end());
            auto hmacRes = CryptoEngine::computeHMAC(chainInputBytes, hmacKey);
            if (hmacRes.fail())
                return Result<void>::Failure(hmacRes.status, "HMAC failed at line " +
                    std::to_string(lineNum));

            std::string computedHmac = CryptoEngine::toHex(hmacRes.value);

            if (computedHmac != storedHmac)
                return Result<void>::Failure(SecurityStatus::ERR_TAMPER_DETECTED,
                    "TAMPER DETECTED at line #" + std::to_string(lineNum) +
                    " — log has been modified!");

            prevHash = storedHmac;
        }

        return Result<void>::Success();
    }

    // ── Print human-readable log ──
    static void printLog(const std::string& logPath, std::ostream& out = std::cout) {
        std::ifstream f(logPath);
        if (!f.is_open()) { out << "Cannot open: " << logPath << "\n"; return; }

        out << std::left
            << std::setw(6)  << "SEQ"
            << std::setw(22) << "TIMESTAMP"
            << std::setw(16) << "USER"
            << std::setw(20) << "ACTION"
            << std::setw(10) << "RESULT"
            << "DETAILS\n"
            << std::string(90, '-') << "\n";

        std::string line;
        while (std::getline(f, line)) {
            if (line.empty()) continue;
            auto parts = split(line, '|');
            if (parts.size() < 6) continue;
            out << std::setw(6)  << parts[0]    // seq
                << std::setw(22) << parts[1]    // timestamp
                << std::setw(16) << parts[2]    // userId
                << std::setw(20) << parts[3]    // action
                << std::setw(10) << parts[4]    // result
                << parts[5]                     // details
                << "\n";
        }
    }

private:
    static std::string loadLastHash(const std::string& logPath) {
        // Initial hash for empty / new log
        static const std::string GENESIS_HASH(64, '0');

        std::ifstream f(logPath);
        if (!f.is_open()) return GENESIS_HASH;

        std::string last, line;
        while (std::getline(f, line))
            if (!line.empty()) last = line;

        if (last.empty()) return GENESIS_HASH;

        auto lastPipe = last.rfind('|');
        if (lastPipe == std::string::npos) return GENESIS_HASH;
        return last.substr(lastPipe + 1);
    }

    static std::string getTimestamp() {
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

    static std::string sanitize(std::string_view s) {
        std::string out;
        for (char c : s) {
            if (c == '|') out += "&#124;"; // escape pipe (our field delimiter)
            else if (c == '\n' || c == '\r') out += ' ';
            else if (c == '\0') out += "\\0";
            else out += c;
        }
        return out;
    }

    static std::vector<std::string> split(const std::string& s, char delim) {
        std::vector<std::string> parts;
        std::istringstream iss(s);
        std::string token;
        while (std::getline(iss, token, delim)) parts.push_back(token);
        return parts;
    }

    std::string   logPath_;
    SecBytes      hmacKey_;
    std::string   lastChainHash_;
    u64_t         seqCounter_ { 0 };
    std::ofstream file_;
    std::mutex    mutex_;
};

} // namespace SecFW
