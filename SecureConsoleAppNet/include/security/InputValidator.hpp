#pragma once
// ============================================================
// InputValidator.hpp — v1.4
// Centralised input validation and sanitisation layer.
//
// v1.4 Changes (Pre-Network Hardening):
//   FIX [BUG-E04]: Add isValidSocketPath() for Unix domain socket paths.
//
//   Root cause in v1.3:
//     isValidPath() enforces a 4096-byte limit (PATH_MAX on Linux).
//     Unix domain socket paths have a MUCH stricter limit:
//     UNIX_PATH_MAX = 108 bytes on Linux (struct sockaddr_un.sun_path).
//     Accepting a socket path longer than 107 bytes (leaving 1 for NUL)
//     causes bind()/connect() to silently truncate the path, potentially
//     connecting to a DIFFERENT socket than intended — a subtle
//     security bug with no error returned by the OS.
//
//     Additionally, abstract namespace sockets (path starting with '\0')
//     have different semantics and must be handled separately.
//     LD_PRELOAD and shell metacharacters in socket paths are especially
//     dangerous since paths are passed to bind() which follows symlinks.
//
//   Fix (additive only — isValidPath() unchanged):
//     isValidSocketPath(path, allowAbstract=false) — new function:
//       - Enforces 107-byte max (108 - 1 NUL terminator)
//       - Rejects abstract namespace unless explicitly opted in
//       - Rejects path traversal (..)
//       - Rejects shell metacharacters
//       - Rejects NUL bytes in non-abstract paths
//       - Enforces that the path is absolute (starts with '/')
//         OR is an abstract path (starts with '\0')
//       - Validates suffix is a regular filename (no trailing slash)
//
//   Also added (additive):
//     Rules::SOCKET_PATH — pre-built ValidationRule for socket path strings
//                          (note: does NOT catch UNIX_PATH_MAX; use
//                           isValidSocketPath() for the definitive check)
//
// Previous fixes (v1.3): all unchanged below.
//
// Standards:
//   OWASP ASVS V5     (Input Validation)
//   OWASP Top-10 A03  (Injection)
//   CERT STR31-C      (no unterminated strings)
//   CERT INT34-C      (no UB integer conversions)
//   NIST SP 800-63B   (password policy)
//   POSIX.1-2017      (UNIX_PATH_MAX / sockaddr_un.sun_path)
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

// ── Platform constants ────────────────────────────────────────────────────────

#if defined(_WIN32) || defined(_WIN64)
    // Windows Named Pipes use \\.\pipe\<name>, max 256 chars total.
    // We use the same constant name for cross-platform code clarity.
    static constexpr std::size_t SECFW_UNIX_PATH_MAX = 256;
#else
    // Linux: struct sockaddr_un.sun_path is 108 bytes (including NUL terminator)
    // → maximum usable path length = 107 characters.
    // macOS/BSD: 104 bytes → max 103. We use the stricter Linux value.
    static constexpr std::size_t SECFW_UNIX_PATH_MAX = 108;
#endif

// ── ValidationRule ────────────────────────────────────────────────────────────

struct ValidationRule {
    std::size_t   minLen        { 1 };
    std::size_t   maxLen        { 256 };
    std::string   pattern       {};
    std::string   allowedChars  {};
    bool          checkSQLi     { true };
    bool          noControlChars{ true };
};

// ── Pre-built rules ───────────────────────────────────────────────────────────

namespace Rules {

    // Username: 3–64 chars, alphanumeric + _ . - only
    inline const ValidationRule USERNAME {
        .minLen        = 3,
        .maxLen        = 64,
        .pattern       = R"(^[A-Za-z0-9_.\-]+$)",
        .allowedChars  = {},
        .checkSQLi     = true,
        .noControlChars= true,
    };

    // Password: 12–128 chars, NIST SP 800-63B complexity
    inline const ValidationRule PASSWORD {
        .minLen        = 12,
        .maxLen        = 128,
        .pattern       = R"(^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/~`]).{12,128}$)",
        .allowedChars  = {},
        .checkSQLi     = false,
        .noControlChars= true,
    };

    // Generic printable text (command arguments, labels, etc.)
    inline const ValidationRule TEXT {
        .minLen        = 1,
        .maxLen        = 512,
        .pattern       = {},
        .allowedChars  = {},
        .checkSQLi     = true,
        .noControlChars= true,
    };

    // Filesystem path: up to PATH_MAX, no control chars
    inline const ValidationRule FILE_PATH {
        .minLen        = 1,
        .maxLen        = 260,
        .pattern       = {},
        .allowedChars  = {},
        .checkSQLi     = false,
        .noControlChars= true,
    };

    // v1.4: Unix domain socket path — string-level check only.
    //
    // IMPORTANT: This rule alone is NOT sufficient for socket paths.
    // You MUST also call isValidSocketPath() which enforces:
    //   - UNIX_PATH_MAX (108 bytes)
    //   - Abstract namespace handling
    //   - Absolute path requirement
    //   - Additional OS-specific constraints
    //
    // This rule exists so you can run validate() for the common checks
    // (control chars, SQLi) before the socket-specific check:
    //
    //   auto r1 = InputValidator::validate(path, Rules::SOCKET_PATH, "socket");
    //   auto r2 = InputValidator::isValidSocketPath(path);

    inline const ValidationRule SOCKET_PATH {
        .minLen        = 2,      // minimum: "/" + one char
        // maxLen uses SECFW_UNIX_PATH_MAX - 1 (NUL terminator not in string)
        .maxLen        = SECFW_UNIX_PATH_MAX - 1,
        .pattern       = {},
        .allowedChars  = {},
        .checkSQLi     = false,  // socket paths may contain chars that look like SQL
        .noControlChars= true,   // NUL, CR, LF all rejected at this level
    };

} // namespace Rules

// ── InputValidator ────────────────────────────────────────────────────────────

class InputValidator final {
public:
    InputValidator()  = delete;
    ~InputValidator() = delete;

    // ── validate ─────────────────────────────────────────────────────────────

    [[nodiscard]] static Result<void> validate(
        std::string_view     value,
        const ValidationRule& rule,
        std::string_view     fieldName = "field")
    {
        if (value.size() < rule.minLen)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                std::string(fieldName) + ": too short (min " +
                std::to_string(rule.minLen) + ")");

        if (value.size() > rule.maxLen)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                std::string(fieldName) + ": too long (max " +
                std::to_string(rule.maxLen) + ")");

        if (rule.noControlChars) {
            for (unsigned char c : value) {
                if (c < 0x20u && c != 0x09u)
                    return Result<void>::Failure(
                        SecurityStatus::ERR_INPUT_INVALID,
                        std::string(fieldName) +
                        ": contains control character (0x" + toHex2(c) + ")");
                if (c == 0x7fu)
                    return Result<void>::Failure(
                        SecurityStatus::ERR_INPUT_INVALID,
                        std::string(fieldName) + ": contains DEL character");
            }
        }

        if (rule.checkSQLi) {
            auto sqliResult = detectSQLi(value);
            if (sqliResult.fail()) return sqliResult;
        }

        if (!rule.allowedChars.empty()) {
            for (char c : value) {
                if (rule.allowedChars.find(c) == std::string::npos)
                    return Result<void>::Failure(
                        SecurityStatus::ERR_INPUT_INVALID,
                        std::string(fieldName) + ": contains disallowed character");
            }
        }

        if (!rule.pattern.empty()) {
            try {
                static thread_local std::regex  re;
                static thread_local std::string lastPat;
                if (lastPat != rule.pattern) {
                    re = std::regex(rule.pattern,
                                    std::regex::ECMAScript | std::regex::optimize);
                    lastPat = rule.pattern;
                }
                if (!std::regex_match(std::string(value), re))
                    return Result<void>::Failure(
                        SecurityStatus::ERR_INPUT_INVALID,
                        std::string(fieldName) + ": does not match required pattern");
            } catch (const std::regex_error& e) {
                return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                    std::string("Regex error for ") + std::string(fieldName) +
                    ": " + e.what());
            }
        }

        return Result<void>::Success();
    }

    // ── parseInteger<T> ──────────────────────────────────────────────────────
    //
    // CERT INT34-C: uses std::from_chars (no UB, no locale dependency).

    template <typename T>
    [[nodiscard]] static Result<T> parseInteger(
        std::string_view input,
        T                minVal = std::numeric_limits<T>::min(),
        T                maxVal = std::numeric_limits<T>::max())
    {
        if (input.empty())
            return Result<T>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "empty integer string");

        T val{};
        auto [ptr, ec] = std::from_chars(input.data(),
                                          input.data() + input.size(), val);

        if (ec != std::errc{})
            return Result<T>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "not a valid integer: '" + std::string(input) + "'");

        if (ptr != input.data() + input.size())
            return Result<T>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "trailing characters after integer: '" + std::string(input) + "'");

        if (val < minVal || val > maxVal)
            return Result<T>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "integer out of range [" + std::to_string(minVal) +
                ", " + std::to_string(maxVal) + "]: " + std::to_string(val));

        return Result<T>::Success(val);
    }

    // ── sanitize — escape control / injection characters ─────────────────────
    //
    // Replaces CR, LF, NUL, other control chars, DEL.
    // Does NOT HTML-escape — use a dedicated encoder for web contexts.

    [[nodiscard]] static std::string sanitize(std::string_view input) {
        std::string out;
        out.reserve(input.size());
        for (unsigned char c : input) {
            switch (c) {
                case '\0': out += "\\0";   break;
                case '\n': out += "\\n";   break;
                case '\r': out += "\\r";   break;
                case '\t': out += "\\t";   break;
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
    // Lightweight SQL-injection heuristic. NOT a replacement for
    // parameterised queries — use both.

    [[nodiscard]] static Result<void> detectSQLi(std::string_view input) {
        std::string upper;
        upper.reserve(input.size());
        for (char c : input)
            upper += static_cast<char>(
                std::toupper(static_cast<unsigned char>(c)));

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

        std::size_t sq = std::count(input.begin(), input.end(), '\'');
        if (sq > 0 && (sq % 2) != 0)
            return Result<void>::Failure(
                SecurityStatus::ERR_INPUT_INVALID,
                "SQL injection heuristic: unbalanced single quotes");

        if (input.find(';') != std::string_view::npos)
            return Result<void>::Failure(
                SecurityStatus::ERR_INPUT_INVALID,
                "SQL injection heuristic: semicolon in input");

        return Result<void>::Success();
    }

    // ── isValidPath — filesystem path check ──────────────────────────────────
    //
    // Rejects traversal, shell metacharacters, NUL bytes.
    // Max length: 4096 (PATH_MAX on Linux).

    [[nodiscard]] static Result<void> isValidPath(std::string_view path) {
        if (path.empty())
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "path is empty");
        if (path.size() > 4096)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "path too long (max 4096)");
        if (path.find("..") != std::string_view::npos)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "path traversal '..' detected");
        if (path.find('\0') != std::string_view::npos)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "NUL byte in path");

        static const std::string_view SHELL_META = "`$|;&<>!{}()";
        for (char c : SHELL_META) {
            if (path.find(c) != std::string_view::npos)
                return Result<void>::Failure(
                    SecurityStatus::ERR_INPUT_INVALID,
                    std::string("shell metacharacter '") + c + "' in path");
        }

        return Result<void>::Success();
    }

    // ── isValidSocketPath — Unix domain socket path check (v1.4 BUG-E04) ─────
    //
    // Validates a path intended for use as a Unix domain socket address.
    // This is STRICTER than isValidPath() in several ways:
    //
    //   1. UNIX_PATH_MAX enforcement:
    //      Linux sockaddr_un.sun_path is 108 bytes; the last byte must be '\0'.
    //      So maximum usable path string length is 107 characters.
    //      Passing a longer path to bind()/connect() causes silent truncation
    //      → could connect to the WRONG socket with no error returned.
    //
    //   2. Abstract namespace sockets:
    //      On Linux, a path starting with '\0' is an "abstract" socket.
    //      These have different lifecycle semantics (auto-deleted when all
    //      FDs close; invisible in filesystem; immune to permission checks).
    //      Accepting abstract paths should be an explicit opt-in.
    //      Set allowAbstract=true only for inter-process scenarios where
    //      filesystem socket files are not suitable (e.g. inside containers).
    //
    //   3. Must be absolute:
    //      Relative socket paths resolve against CWD which changes unpredictably.
    //      We require '/' prefix (or '\0' for abstract).
    //
    //   4. No trailing slash:
    //      bind() would fail; better to catch it at validation time.
    //
    //   5. All checks from isValidPath() also apply (traversal, metacharacters).
    //
    // Parameters:
    //   path          — the socket path string to validate
    //   allowAbstract — if true, accept paths starting with '\0'
    //                   (abstract namespace). Default: false.
    //
    // Returns Result<void>::Success() if path is safe to use in bind()/connect().

    [[nodiscard]] static Result<void> isValidSocketPath(
        std::string_view path,
        bool             allowAbstract = false)
    {
        // ── Empty check ───────────────────────────────────────────────────────
        if (path.empty())
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "socket path is empty");

        // ── Abstract namespace check ──────────────────────────────────────────
        bool isAbstract = (!path.empty() && path[0] == '\0');

        if (isAbstract) {
            if (!allowAbstract)
                return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "abstract namespace socket paths are not allowed "
                    "(path starts with NUL byte)");

#ifdef _WIN32
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "abstract namespace sockets are Linux-only; "
                "use Named Pipes on Windows");
#endif
            // For abstract paths: validate the name portion (after the leading NUL)
            std::string_view name = path.substr(1);

            // UNIX_PATH_MAX includes the leading NUL, so name can be at most
            // SECFW_UNIX_PATH_MAX - 1 characters (the leading NUL occupies byte 0).
            if (name.size() > SECFW_UNIX_PATH_MAX - 1)
                return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "abstract socket name too long: " +
                    std::to_string(name.size()) + " bytes (max " +
                    std::to_string(SECFW_UNIX_PATH_MAX - 1) + ")");

            // Abstract names may contain any byte except '\0'
            if (name.find('\0') != std::string_view::npos)
                return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "abstract socket name contains embedded NUL byte");

            return Result<void>::Success();
        }

        // ── Filesystem socket path checks ─────────────────────────────────────

        // 1. UNIX_PATH_MAX enforcement (the critical fix for BUG-E04)
        //    We check strictly: path must fit in sun_path WITH room for '\0'.
        //    SECFW_UNIX_PATH_MAX = 108, so max usable length = 107.
        if (path.size() >= SECFW_UNIX_PATH_MAX)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "socket path too long: " + std::to_string(path.size()) +
                " bytes (UNIX_PATH_MAX allows max " +
                std::to_string(SECFW_UNIX_PATH_MAX - 1) + " + NUL terminator)");

        // 2. Must be absolute (starts with '/')
#ifndef _WIN32
        if (path[0] != '/')
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "socket path must be absolute (start with '/'): got '" +
                std::string(path.substr(0, 32)) + "'");
#else
        // Windows Named Pipe paths must start with \\.\pipe\
        static constexpr std::string_view PIPE_PREFIX = "\\\\.\\pipe\\";
        if (path.substr(0, PIPE_PREFIX.size()) != PIPE_PREFIX)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "Windows socket path must start with \\\\.\\pipe\\");
#endif

        // 3. No trailing slash
        if (path.back() == '/')
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "socket path must not end with '/'");

        // 4. Path traversal
        if (path.find("..") != std::string_view::npos)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "path traversal '..' in socket path");

        // 5. NUL bytes (would truncate in sockaddr_un.sun_path silently)
        if (path.find('\0') != std::string_view::npos)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "NUL byte in socket path — would cause silent truncation in bind()");

        // 6. Shell metacharacters — dangerous if path is logged or shell-expanded
        static const std::string_view SHELL_META = "`$|;&<>!{}()";
        for (char c : SHELL_META) {
            if (path.find(c) != std::string_view::npos)
                return Result<void>::Failure(
                    SecurityStatus::ERR_INPUT_INVALID,
                    std::string("shell metacharacter '") + c +
                    "' in socket path");
        }

        // 7. Whitespace — bind() will succeed but the path is fragile
        for (char c : path) {
            if (c == ' ' || c == '\t')
                return Result<void>::Failure(
                    SecurityStatus::ERR_INPUT_INVALID,
                    "whitespace in socket path — use underscore or hyphen instead");
        }

        return Result<void>::Success();
    }

private:
    // ── toHex2 — format one byte as two hex digits ────────────────────────────

    static std::string toHex2(unsigned char c) {
        const char* hex = "0123456789abcdef";
        return { hex[(c >> 4) & 0xF], hex[c & 0xF] };
    }
};

} // namespace SecFW
