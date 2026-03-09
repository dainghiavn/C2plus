#pragma once
// ============================================================
// InputValidator.hpp
// Standards: OWASP Input Validation, CERT STR02-C, STR03-C
// ============================================================
#include "SecureCore.hpp"
#include <regex>
#include <charconv>
#include <system_error>

namespace SecFW {

struct ValidationRule {
    std::size_t  minLen      { 0 };
    std::size_t  maxLen      { 4096 };
    std::string  regexPattern{};
    bool         allowUnicode{ false };
    bool         allowHTML   { false };
    bool         required    { true };
};

namespace Rules {
    inline const ValidationRule USERNAME = {
        .minLen = 3, .maxLen = 32,
        .regexPattern = R"(^[a-zA-Z0-9_\-\.]+$)",
        .allowUnicode = false
    };
    inline const ValidationRule PASSWORD = {
        .minLen = 12, .maxLen = 128,
        .regexPattern = R"(^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[^\s]+$)"
    };
    inline const ValidationRule EMAIL = {
        .minLen = 5, .maxLen = 254,
        .regexPattern = R"(^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$)"
    };
    inline const ValidationRule FILENAME = {
        .minLen = 1, .maxLen = 255,
        .regexPattern = R"(^[a-zA-Z0-9_\-\.]+$)"
    };
}

class InputValidator final {
public:
    [[nodiscard]] static Result<std::string> validate(
        std::string_view input,
        const ValidationRule& rule,
        std::string_view fieldName = "input")
    {
        if (input.find('\0') != std::string_view::npos)
            return Result<std::string>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                std::string(fieldName) + ": Null byte detected");

        if (rule.required && input.empty())
            return Result<std::string>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                std::string(fieldName) + ": Required field is empty");

        if (input.size() < rule.minLen || input.size() > rule.maxLen)
            return Result<std::string>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                std::string(fieldName) + ": Length out of range [" +
                std::to_string(rule.minLen) + ", " + std::to_string(rule.maxLen) + "]");

        if (!rule.allowUnicode) {
            for (unsigned char c : input)
                if (c > 127)
                    return Result<std::string>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                        std::string(fieldName) + ": Non-ASCII character");
        }

        if (!rule.allowHTML) {
            if (input.find('<') != std::string_view::npos ||
                input.find('>') != std::string_view::npos)
                return Result<std::string>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    std::string(fieldName) + ": HTML tags not allowed");
        }

        if (!rule.regexPattern.empty()) {
            try {
                std::regex re(rule.regexPattern);
                if (!std::regex_match(std::string(input), re))
                    return Result<std::string>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                        std::string(fieldName) + ": Pattern validation failed");
            } catch (const std::regex_error& e) {
                return Result<std::string>::Failure(SecurityStatus::ERR_INTERNAL,
                    "Regex error: " + std::string(e.what()));
            }
        }
        return Result<std::string>::Success(std::string(input));
    }

    [[nodiscard]] static Result<std::string> sanitizePath(std::string_view path) {
        std::string p(path);
        const std::vector<std::string> dangerous = {
            "..", "//", "\\\\", "%2e%2e", "%252e", "..%2f", "%2f.."
        };
        for (const auto& d : dangerous)
            if (p.find(d) != std::string::npos)
                return Result<std::string>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "Path traversal detected: " + d);
        std::replace(p.begin(), p.end(), '\\', '/');
        return Result<std::string>::Success(p);
    }

    template<typename IntT>
    [[nodiscard]] static Result<IntT> parseInteger(
        std::string_view input,
        IntT minVal = std::numeric_limits<IntT>::min(),
        IntT maxVal = std::numeric_limits<IntT>::max())
    {
        IntT value{};
        auto [ptr, ec] = std::from_chars(input.begin(), input.end(), value);
        if (ec != std::errc{} || ptr != input.end())
            return Result<IntT>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "Invalid integer format");
        if (value < minVal || value > maxVal)
            return Result<IntT>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "Integer out of allowed range");
        return Result<IntT>::Success(value);
    }

    [[nodiscard]] static bool hasSQLInjection(std::string_view input) noexcept {
        static const std::vector<std::string> patterns = {
            "';", "--", "/*", "*/", "xp_", "exec ", "union ",
            "select ", "drop ", "insert ", "update ", "delete ", "1=1", "or 1"
        };
        std::string lower(input);
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (const auto& p : patterns)
            if (lower.find(p) != std::string::npos) return true;
        return false;
    }
};

} // namespace SecFW
