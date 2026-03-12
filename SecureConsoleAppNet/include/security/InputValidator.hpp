#pragma once
// ============================================================
// InputValidator.hpp — v1.3
// Centralised input validation and sanitisation layer.
//
// Provides:
//   ValidationRule           — constraint struct (minLen, maxLen, regex)
//   Rules::USERNAME          — pre-built rule for usernames
//   Rules::PASSWORD          — pre-built rule for passwords
//   InputValidator::validate()      — validate a string value
//   InputValidator::parseInteger<T>() — safe integer parse with bounds
//   InputValidator::sanitize()      — strip control / injection chars
//
// Standards:
//   OWASP ASVS V5  (Input Validation)
//   OWASP Top-10 A03 (Injection)
//   CERT STR31-C   (no unterminated strings)
//   CERT INT34-C   (no UB integer conversions)
//   NIST SP 800-63B (password policy)
// ============================================================

#include "SecureCore.hpp"
#include <string>
#include <string_view>
#include <regex>
#include <algorithm>
#include <charconv>
#include <limits>
#include <cctype>
#include <array>
#include <optional>
#include <cstdint>

namespace SecFW {

// ── ValidationRule ────────────────────────────────────────────────────────────

struct ValidationRule {
    std::size_t   minLen       { 1 };
    std::size_t   maxLen       { 256 };

    // Optional regex pattern (ECMAScript). Empty string = no pattern check.
    std::string   pattern      {};

    // Optional whitelist of allowed characters. Empty = accept all (after
    // minLen/maxLen and pattern checks).  Blacklist is NOT used here —
    // explicit whitelist is safer (OWASP A03).
    std::string   allowedChars {};

    // Whether the value must not match any known SQL injection pattern.
    bool          checkSQLi    { true };

    // Whether to reject strings containing NUL / control characters.
    bool          noControlChars { true };
};

// ── Pre-built rules ───────────────────────────────────────────────────────────

namespace Rules {

    // Username: 3–64 chars, alphanumeric + _ . - only
    // NIST SP 800-63B §5.1.1 guidance: disallow whitespace and control chars
    inline const ValidationRule USERNAME {
        .minLen       = 3,
        .maxLen       = 64,
        .pattern      = R"(^[A-Za-z0-9_.\-]+$)",
        .allowedChars = {},
        .checkSQLi    = true,
        .noControlChars = true,
    };

    // Password: 12–128 chars, must contain at least one upper, lower, digit,
    // special.  NUL bytes rejected.  (NIST SP 800-63B §5.1.1.2 complexity)
    inline const ValidationRule PASSWORD {
        .minLen       = 12,
        .maxLen       = 128,
        // Require ≥1 uppercase, ≥1 lowercase, ≥1 digit, ≥1 special
        .pattern      = R"(^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/~`]).{12,128}$)",
        .allowedChars = {},
        .checkSQLi    = false,   // passwords may legitimately contain SQL chars
        .noControlChars = true,
    };

    // Generic printable text (e.g. command arguments)
    inline const ValidationRule TEXT {
        .minLen       = 1,
        .maxLen       = 512,
        .pattern      = {},
        .allowedChars = {},
        .checkSQLi    = true,
        .noControlChars = true,
    };

    // File path: 1–260 chars, allow path separators and common filesystem chars
    inline const ValidationRule FILE_PATH {
        .minLen       = 1,
        .maxLen       = 260,
        .pattern      = {},
        .allowedChars = {},
        .checkSQLi    = false,
        .noControlChars = true,
    };

} // namespace Rules

// ── InputValidator ────────────────────────────────────────────────────────────

class InputValidator final {
public:
    InputValidator()  = delete;
    ~InputValidator() = delete;

    // ── validate ─────────────────────────────────────────────────────────────
    //
    // Returns Result<void>::Success() if the value passes every check in
    // `rule`.  Returns Failure with a descriptive message otherwise.
    //
    // fieldName is included in error messages for caller context only;
    // it MUST already be trusted (do not pass user-supplied data here).

    [[nodiscard]] static Result<void> validate(
        std::string_view    value,
        const ValidationRule& rule,
        std::string_view    fieldName = "field")
    {
        // ── Length ────────────────────────────────────────────────────────
        if (value.size() < rule.minLen)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                std::string(fieldName) + ": too short (min " +
                std::to_string(rule.minLen) + ")");

        if (value.size() > rule.maxLen)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                std::string(fieldName) + ": too long (max " +
                std::to_string(rule.maxLen) + ")");

        // ── Control characters ────────────────────────────────────────────
        if (rule.noControlChars) {
            for (unsigned char c : value) {
                if (c < 0x20u && c != 0x09u)  // allow TAB, reject other ctrl
                    return Result<void>::Failure(
                        SecurityStatus::ERR_INPUT_INVALID,
                        std::string(fieldName) + ": contains control character (0x" +
                        toHex2(c) + ")");
                if (c == 0x7fu)
                    return Result<void>::Failure(
                        SecurityStatus::ERR_INPUT_INVALID,
                        std::string(fieldName) + ": contains DEL character");
            }
        }

        // ── SQL injection detection ───────────────────────────────────────
        if (rule.checkSQLi) {
            auto sqliResult = detectSQLi(value);
            if (sqliResult.fail()) return sqliResult;
        }

        // ── Whitelist characters ──────────────────────────────────────────
        if (!rule.allowedChars.empty()) {
            for (char c : value) {
                if (rule.allowedChars.find(c) == std::string::npos)
                    return Result<void>::Failure(
                        SecurityStatus::ERR_INPUT_INVALID,
                        std::string(fieldName) + ": contains disallowed character");
            }
        }

        // ── Regex pattern ─────────────────────────────────────────────────
        if (!rule.pattern.empty()) {
            try {
                static thread_local std::regex re;
                static thread_local std::string lastPat;
                if (lastPat != rule.pattern) {
                    re = std::regex(rule.pattern, std::regex::ECMAScript | std::regex::optimize);
                    lastPat = rule.pattern;
                }
                std::string s(value);
                if (!std::regex_match(s, re))
                    return Result<void>::Failure(
                        SecurityStatus::ERR_INPUT_INVALID,
                        std::string(fieldName) + ": does not match required pattern");
            }
            catch (const std::regex_error& e) {
                return Result<void>::Failure(
                    SecurityStatus::ERR_INTERNAL,
                    std::string("Regex error for ") + std::string(fieldName) + ": " + e.what());
            }
        }

        return Result<void>::Success();
    }

    // ── parseInteger<T> ──────────────────────────────────────────────────────
    //
    // Safely parse an integer from a string_view.  Returns Failure if:
    //   - the string contains non-numeric characters
    //   - the value is out of [minVal, maxVal]
    //
    // CERT INT34-C: uses std::from_chars (no UB, no locale dependency).

    template <typename T>
    [[nodiscard]] static Result<T> parseInteger(
        std::string_view sv,
        T minVal = std::numeric_limits<T>::min(),
        T maxVal = std::numeric_limits<T>::max())
    {
        static_assert(std::is_integral_v<T>, "T must be integral");

        if (sv.empty())
            return Result<T>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "empty integer string");

        T parsed{};
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), parsed);

        if (ec == std::errc::invalid_argument)
            return Result<T>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "not a valid integer: '" + std::string(sv) + "'");

        if (ec == std::errc::result_out_of_range)
            return Result<T>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "integer out of type range: '" + std::string(sv) + "'");

        if (ptr != sv.data() + sv.size())
            return Result<T>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "trailing characters after integer: '" + std::string(sv) + "'");

        if (parsed < minVal || parsed > maxVal)
            return Result<T>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "integer " + std::string(sv) + " out of bounds [" +
                std::to_string(minVal) + ", " + std::to_string(maxVal) + "]");

        return Result<T>::Success(parsed);
    }

    // ── sanitize ─────────────────────────────────────────────────────────────
    //
    // Returns a copy of `input` safe for embedding in structured log lines
    // or other single-line output formats.  Replaces:
    //   - CR (\r), LF (\n), NUL (\0) → \\r / \\n / \\0  (log injection, BUG-18)
    //   - other control chars < 0x20  → \xHH
    //   - DEL (0x7f)                  → \x7f
    // Does NOT HTML-escape — use a dedicated HTML encoder for web contexts.

    [[nodiscard]] static std::string sanitize(std::string_view input) {
        std::string out;
        out.reserve(input.size());
        for (unsigned char c : input) {
            switch (c) {
                case '\0': out += "\\0";  break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                case 0x7f: out += "\\x7f"; break;
                default:
                    if (c < 0x20u) {
                        out += "\\x";
                        out += toHex2(c);
                    } else {
                        out += static_cast<char>(c);
                    }
                    break;
            }
        }
        return out;
    }

    // ── detectSQLi ───────────────────────────────────────────────────────────
    //
    // Lightweight heuristic SQL-injection detector.
    // NOT a replacement for parameterised queries — use both.
    // OWASP A03:2021 (Injection); CERT STR31-C.

    [[nodiscard]] static Result<void> detectSQLi(std::string_view input) {
        // Normalise to upper-case for case-insensitive matching
        std::string upper;
        upper.reserve(input.size());
        for (char c : input)
            upper += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

        // Classic keywords that appear in injection payloads
        static const std::array<std::string_view, 18> KEYWORDS {{
            "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ",
            "UNION ",  "CREATE ", "ALTER ",  "EXEC ",   "EXECUTE ",
            "TRUNCATE ", "DECLARE ", "CAST(",  "CONVERT(",
            "XP_",    "SP_",    "--",  "/*"
        }};

        for (std::string_view kw : KEYWORDS) {
            if (upper.find(kw) != std::string::npos)
                return Result<void>::Failure(
                    SecurityStatus::ERR_INPUT_INVALID,
                    "SQL injection pattern detected: '" + std::string(kw) + "'");
        }

        // Balanced-quote heuristic: odd number of single-quotes is suspicious
        std::size_t singleQuotes = std::count(input.begin(), input.end(), '\'');
        if (singleQuotes > 0 && (singleQuotes % 2) != 0)
            return Result<void>::Failure(
                SecurityStatus::ERR_INPUT_INVALID,
                "SQL injection heuristic: unbalanced single quotes");

        // Stacked queries
        if (input.find(';') != std::string_view::npos)
            return Result<void>::Failure(
                SecurityStatus::ERR_INPUT_INVALID,
                "SQL injection heuristic: semicolon in input");

        return Result<void>::Success();
    }

    // ── isValidPath ──────────────────────────────────────────────────────────
    //
    // Reject obvious path traversal and shell-injection sequences.
    // Complements OS-level access controls — not a replacement.

    [[nodiscard]] static Result<void> isValidPath(std::string_view path) {
        if (path.empty())
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "path is empty");

        if (path.size() > 4096)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "path too long");

        // Path traversal
        if (path.find("..") != std::string_view::npos)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "path traversal sequence '..' detected");

        // NUL byte in path — can trick some OS parsers
        if (path.find('\0') != std::string_view::npos)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "NUL byte in path");

        // Shell metacharacters
        static const std::string_view SHELL_META = "`$|;&<>!{}()";
        for (char c : SHELL_META) {
            if (path.find(c) != std::string_view::npos)
                return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    std::string("shell metacharacter '") + c + "' in path");
        }

        return Result<void>::Success();
    }

private:
    [[nodiscard]] static std::string toHex2(unsigned char c) {
        constexpr char hex[] = "0123456789abcdef";
        return { hex[(c >> 4) & 0x0fu], hex[c & 0x0fu] };
    }
};

} // namespace SecFW
