#pragma once
// ============================================================
// SilentToken.hpp — v1.3
// HMAC-SHA256 self-contained signed token for --silent mode.
//
// Token format (three dot-separated Base64URL segments):
//   BASE64URL(header) . BASE64URL(payload) . BASE64URL(hmac)
//
// Header (JSON, fixed):
//   {"alg":"HMAC-SHA256","v":1}
//
// Payload (JSON, all fields required):
//   {
//     "jti": "<32-char hex random>",   unique token ID
//     "sub": "<username>",             subject
//     "rol": <u32 bitmask>,            role flags at issuance
//     "iat": <unix seconds>,           issued-at
//     "exp": <unix seconds>,           expiry
//     "scp": "ro"                      scope — always read-only, hardcoded
//   }
//
// HMAC:
//   HMAC-SHA256(header_b64 + "." + payload_b64, silentTokenKey)
//
// Signing key:
//   KeyDerivation::KeyBundle::silentTokenKey
//   (domain "secfw-silent-token-v1" — never the raw master key)
//
// Revocation:
//   Revoked JTIs stored in memory + optional persist file.
//   In-memory set is authoritative; persist is for crash recovery.
//
// Standards:
//   NIST SP 800-63B §6.2 (bearer token)
//   OWASP ASVS V3.2    (session token)
//   CERT MSC39-C       (constant-time comparison)
// ============================================================

#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include "InputValidator.hpp"
#include <string>
#include <string_view>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <span>

namespace SecFW {

// ── Token TTL limits ──────────────────────────────────────────────────────────
static constexpr int SILENT_TOKEN_TTL_DEFAULT  =  3600;   //  1 hour  (default)
static constexpr int SILENT_TOKEN_TTL_MAX      = 86400;   // 24 hours (hard ceiling)
static constexpr int SILENT_TOKEN_TTL_MIN      =   300;   //  5 min   (hard floor)

// ── SilentTokenPayload ────────────────────────────────────────────────────────

struct SilentTokenPayload {
    std::string jti;          // unique token ID (32 hex chars = 16 random bytes)
    std::string sub;          // username
    u32_t       rol  { 0 };   // role bitmask at issuance
    int64_t     iat  { 0 };   // issued-at  (unix seconds)
    int64_t     exp  { 0 };   // expiry     (unix seconds)
    // scp is always "ro" — not stored in struct, enforced at verify time
};

// ── SilentTokenManager ────────────────────────────────────────────────────────

class SilentTokenManager final {
public:
    // Factory — returns Result<> instead of throwing (CERT ERR50-CPP)
    // signingKey: 32-byte key from KeyDerivation::KeyBundle::silentTokenKey
    // revokePersistPath: optional file path for JTI revocation persistence
    [[nodiscard]] static Result<SilentTokenManager> create(
        std::span<const byte_t> signingKey,
        std::string             revokePersistPath = "")
    {
        if (signingKey.size() != 32)
            return Result<SilentTokenManager>::Failure(
                SecurityStatus::ERR_CRYPTO_FAIL,
                "SilentTokenManager: signing key must be exactly 32 bytes");
        SilentTokenManager mgr;
        mgr.signingKey_.assign(signingKey.begin(), signingKey.end());
        mgr.revokePersistPath_ = std::move(revokePersistPath);
        mgr.loadRevokedSet();
        return Result<SilentTokenManager>::Success(std::move(mgr));
    }

    ~SilentTokenManager() { persistRevokedSet(); }

    // Non-copyable — contains sensitive key material
    SilentTokenManager(const SilentTokenManager&)            = delete;
    SilentTokenManager& operator=(const SilentTokenManager&) = delete;
    SilentTokenManager(SilentTokenManager&&)                 = default;
    SilentTokenManager& operator=(SilentTokenManager&&)      = default;

    // ── issue ─────────────────────────────────────────────────────────────────
    //
    // Create and sign a new token for the given user/role.
    // ttlSeconds: clamped to [SILENT_TOKEN_TTL_MIN, SILENT_TOKEN_TTL_MAX].
    // Returns the complete token string on success.

    [[nodiscard]] Result<std::string> issue(
        std::string_view username,
        u32_t            roleFlags,
        int              ttlSeconds = SILENT_TOKEN_TTL_DEFAULT)
    {
        // Validate username
        auto uv = InputValidator::validate(username, Rules::USERNAME, "username");
        if (uv.fail())
            return Result<std::string>::Failure(uv.status,
                "SilentToken::issue: " + uv.message);

        // Clamp TTL
        ttlSeconds = clamp(ttlSeconds, SILENT_TOKEN_TTL_MIN, SILENT_TOKEN_TTL_MAX);

        // Generate random JTI (16 bytes → 32 hex chars)
        auto jtiRes = CryptoEngine::randomBytes(16);
        if (jtiRes.fail())
            return Result<std::string>::Failure(jtiRes.status,
                "SilentToken::issue: cannot generate JTI: " + jtiRes.message);

        auto now = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        SilentTokenPayload payload {
            .jti = CryptoEngine::toHex(jtiRes.value),
            .sub = std::string(username),
            .rol = roleFlags,
            .iat = now,
            .exp = now + ttlSeconds,
        };

        return buildToken(payload);
    }

    // ── verify ────────────────────────────────────────────────────────────────
    //
    // Parse, validate signature, check expiry, check revocation.
    // Returns payload on success.
    // Does NOT check role — caller is responsible for role authorization.

    [[nodiscard]] Result<SilentTokenPayload> verify(std::string_view tokenStr) const {
        // ── Split into 3 segments ──────────────────────────────────────────
        auto segments = splitDots(tokenStr);
        if (segments.size() != 3)
            return Result<SilentTokenPayload>::Failure(
                SecurityStatus::ERR_AUTH_FAILED,
                "Malformed token: expected 3 segments");

        const std::string& headerB64  = segments[0];
        const std::string& payloadB64 = segments[1];
        const std::string& hmacB64    = segments[2];

        // ── Verify header ─────────────────────────────────────────────────
        auto headerJson = base64UrlDecode(headerB64);
        if (headerJson.empty())
            return Result<SilentTokenPayload>::Failure(
                SecurityStatus::ERR_AUTH_FAILED, "Invalid token header encoding");

        if (headerJson != R"({"alg":"HMAC-SHA256","v":1})")
            return Result<SilentTokenPayload>::Failure(
                SecurityStatus::ERR_AUTH_FAILED, "Unsupported token algorithm");

        // ── Recompute HMAC ────────────────────────────────────────────────
        std::string sigInput = headerB64 + "." + payloadB64;
        SecBytes sigInputBytes(sigInput.begin(), sigInput.end());
        auto hmacRes = CryptoEngine::computeHMAC(sigInputBytes, signingKey_);
        if (hmacRes.fail())
            return Result<SilentTokenPayload>::Failure(hmacRes.status,
                "Token HMAC computation failed: " + hmacRes.message);

        // ── Constant-time HMAC comparison (CERT MSC39-C) ─────────────────
        auto storedHmacBytes = base64UrlDecodeBytes(hmacB64);
        if (!constantTimeEqual(hmacRes.value, storedHmacBytes))
            return Result<SilentTokenPayload>::Failure(
                SecurityStatus::ERR_AUTH_FAILED,
                "Token signature invalid");

        // ── Parse payload ─────────────────────────────────────────────────
        auto payloadJson = base64UrlDecode(payloadB64);
        if (payloadJson.empty())
            return Result<SilentTokenPayload>::Failure(
                SecurityStatus::ERR_AUTH_FAILED, "Invalid token payload encoding");

        auto parseRes = parsePayload(payloadJson);
        if (parseRes.fail())
            return Result<SilentTokenPayload>::Failure(parseRes.status, parseRes.message);

        const auto& pl = parseRes.value;

        // ── Check expiry ──────────────────────────────────────────────────
        auto now = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        if (now >= pl.exp)
            return Result<SilentTokenPayload>::Failure(
                SecurityStatus::ERR_AUTH_FAILED,
                "Token expired");

        // Reject tokens issued in the future (clock skew attack)
        if (pl.iat > now + 30)
            return Result<SilentTokenPayload>::Failure(
                SecurityStatus::ERR_AUTH_FAILED,
                "Token issued in the future — clock skew detected");

        // ── Check revocation ──────────────────────────────────────────────
        {
            std::lock_guard<std::mutex> lock(revokedMutex_);
            if (revokedJtis_.count(pl.jti))
                return Result<SilentTokenPayload>::Failure(
                    SecurityStatus::ERR_AUTH_FAILED,
                    "Token has been revoked");
        }

        return Result<SilentTokenPayload>::Success(pl);
    }

    // ── revoke ────────────────────────────────────────────────────────────────
    //
    // Add a JTI to the revoked set.
    // The token string is verified first to prevent accepting garbage JTIs.

    [[nodiscard]] Result<void> revoke(std::string_view tokenStr) {
        // Parse token to get JTI — but don't require valid expiry for revocation
        auto segments = splitDots(tokenStr);
        if (segments.size() != 3)
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "Malformed token");

        // Verify HMAC before accepting the JTI (prevent JTI injection via fake revoke)
        std::string sigInput = segments[0] + "." + segments[1];
        SecBytes sigInputBytes(sigInput.begin(), sigInput.end());
        auto hmacRes = CryptoEngine::computeHMAC(sigInputBytes, signingKey_);
        if (hmacRes.fail())
            return Result<void>::Failure(hmacRes.status, hmacRes.message);

        auto storedHmacBytes = base64UrlDecodeBytes(segments[2]);
        if (!constantTimeEqual(hmacRes.value, storedHmacBytes))
            return Result<void>::Failure(SecurityStatus::ERR_AUTH_FAILED,
                "Cannot revoke: invalid token signature");

        auto payloadJson = base64UrlDecode(segments[1]);
        auto parseRes    = parsePayload(payloadJson);
        if (parseRes.fail())
            return Result<void>::Failure(parseRes.status, parseRes.message);

        {
            std::lock_guard<std::mutex> lock(revokedMutex_);
            revokedJtis_.insert(parseRes.value.jti);
        }
        persistRevokedSet();
        return Result<void>::Success();
    }

    // ── revokeById ────────────────────────────────────────────────────────────
    //
    // Revoke by raw JTI string — only for admin use (no signature check).
    // Caller MUST have verified the JTI is legitimate.

    void revokeById(const std::string& jti) {
        std::lock_guard<std::mutex> lock(revokedMutex_);
        revokedJtis_.insert(jti);
    }

    // ── isRevoked ─────────────────────────────────────────────────────────────
    [[nodiscard]] bool isRevoked(const std::string& jti) const {
        std::lock_guard<std::mutex> lock(revokedMutex_);
        return revokedJtis_.count(jti) > 0;
    }

    [[nodiscard]] std::size_t revokedCount() const {
        std::lock_guard<std::mutex> lock(revokedMutex_);
        return revokedJtis_.size();
    }

    // ── formatExpiry ──────────────────────────────────────────────────────────
    // Returns ISO-8601 UTC string for a unix timestamp
    [[nodiscard]] static std::string formatTimestamp(int64_t unixSeconds) {
        time_t t = static_cast<time_t>(unixSeconds);
        struct tm tm_buf {};
#ifdef _WIN32
        gmtime_s(&tm_buf, &t);
#else
        gmtime_r(&t, &tm_buf);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
        return buf;
    }

private:
    SilentTokenManager() = default;  // private — use create()

    SecBytes                       signingKey_;
    std::string                    revokePersistPath_;
    mutable std::mutex             revokedMutex_;
    std::unordered_set<std::string> revokedJtis_;

    // ── buildToken ────────────────────────────────────────────────────────────

    [[nodiscard]] Result<std::string> buildToken(const SilentTokenPayload& pl) const {
        // Header — fixed
        std::string headerJson = R"({"alg":"HMAC-SHA256","v":1})";
        std::string headerB64  = base64UrlEncode(
            reinterpret_cast<const byte_t*>(headerJson.data()), headerJson.size());

        // Payload — minimal hand-rolled JSON (no external lib)
        std::ostringstream pj;
        pj << "{"
           << R"("jti":")" << pl.jti << "\","
           << R"("sub":")" << jsonEscape(pl.sub) << "\","
           << R"("rol":)"  << pl.rol << ","
           << R"("iat":)"  << pl.iat << ","
           << R"("exp":)"  << pl.exp << ","
           << R"("scp":"ro")"
           << "}";
        std::string payloadJson = pj.str();
        std::string payloadB64  = base64UrlEncode(
            reinterpret_cast<const byte_t*>(payloadJson.data()), payloadJson.size());

        // HMAC over header.payload
        std::string sigInput = headerB64 + "." + payloadB64;
        SecBytes sigBytes(sigInput.begin(), sigInput.end());
        auto hmacRes = CryptoEngine::computeHMAC(sigBytes, signingKey_);
        if (hmacRes.fail())
            return Result<std::string>::Failure(hmacRes.status,
                "Token signing failed: " + hmacRes.message);

        std::string hmacB64 = base64UrlEncode(hmacRes.value.data(), hmacRes.value.size());

        return Result<std::string>::Success(headerB64 + "." + payloadB64 + "." + hmacB64);
    }

    // ── parsePayload ──────────────────────────────────────────────────────────
    //
    // Minimal JSON parser — only reads the exact fields we write.
    // No external library dependency.

    [[nodiscard]] static Result<SilentTokenPayload> parsePayload(const std::string& json) {
        SilentTokenPayload pl;

        auto extractStr = [&](const std::string& key) -> std::optional<std::string> {
            // Find "key":"value"
            std::string search = "\"" + key + "\":\"";
            auto pos = json.find(search);
            if (pos == std::string::npos) return std::nullopt;
            pos += search.size();
            auto end = json.find('"', pos);
            if (end == std::string::npos) return std::nullopt;
            return json.substr(pos, end - pos);
        };

        auto extractInt = [&](const std::string& key) -> std::optional<int64_t> {
            std::string search = "\"" + key + "\":";
            auto pos = json.find(search);
            if (pos == std::string::npos) return std::nullopt;
            pos += search.size();
            // skip whitespace
            while (pos < json.size() && json[pos] == ' ') ++pos;
            std::string num;
            while (pos < json.size() && (std::isdigit(json[pos]) || json[pos] == '-'))
                num += json[pos++];
            if (num.empty()) return std::nullopt;
            try { return std::stoll(num); } catch (...) { return std::nullopt; }
        };

        auto jti = extractStr("jti");
        auto sub = extractStr("sub");
        auto scp = extractStr("scp");
        auto rol = extractInt("rol");
        auto iat = extractInt("iat");
        auto exp = extractInt("exp");

        if (!jti || !sub || !scp || !rol || !iat || !exp)
            return Result<SilentTokenPayload>::Failure(
                SecurityStatus::ERR_AUTH_FAILED,
                "Token payload missing required field(s)");

        // Enforce scope — must be exactly "ro"
        if (*scp != "ro")
            return Result<SilentTokenPayload>::Failure(
                SecurityStatus::ERR_AUTH_FAILED,
                "Token scope invalid — only 'ro' is accepted");

        // Validate JTI format: exactly 32 hex chars
        if (jti->size() != 32)
            return Result<SilentTokenPayload>::Failure(
                SecurityStatus::ERR_AUTH_FAILED,
                "Token JTI has invalid length");
        for (char c : *jti)
            if (!std::isxdigit(static_cast<unsigned char>(c)))
                return Result<SilentTokenPayload>::Failure(
                    SecurityStatus::ERR_AUTH_FAILED,
                    "Token JTI contains non-hex character");

        // Validate username in sub
        auto uv = InputValidator::validate(*sub, Rules::USERNAME, "sub");
        if (uv.fail())
            return Result<SilentTokenPayload>::Failure(uv.status,
                "Token sub field invalid: " + uv.message);

        pl.jti = *jti;
        pl.sub = *sub;
        pl.rol = static_cast<u32_t>(*rol);
        pl.iat = *iat;
        pl.exp = *exp;

        return Result<SilentTokenPayload>::Success(pl);
    }

    // ── Base64URL encode/decode ───────────────────────────────────────────────
    // RFC 4648 §5: no padding, + → -, / → _

    [[nodiscard]] static std::string base64UrlEncode(const byte_t* data, std::size_t len) {
        static constexpr char TABLE[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string out;
        out.reserve((len + 2) / 3 * 4);
        for (std::size_t i = 0; i < len; i += 3) {
            uint32_t b = (static_cast<uint32_t>(data[i]) << 16);
            if (i + 1 < len) b |= (static_cast<uint32_t>(data[i+1]) << 8);
            if (i + 2 < len) b |= static_cast<uint32_t>(data[i+2]);
            out += TABLE[(b >> 18) & 0x3Fu];
            out += TABLE[(b >> 12) & 0x3Fu];
            if (i + 1 < len) out += TABLE[(b >>  6) & 0x3Fu];
            if (i + 2 < len) out += TABLE[ b        & 0x3Fu];
        }
        return out;  // no padding per RFC 7515
    }

    [[nodiscard]] static std::string base64UrlDecode(const std::string& s) {
        auto bytes = base64UrlDecodeBytes(s);
        return std::string(bytes.begin(), bytes.end());
    }

    [[nodiscard]] static SecBytes base64UrlDecodeBytes(const std::string& s) {
        auto val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '-')             return 62;
            if (c == '_')             return 63;
            return -1;
        };

        SecBytes out;
        out.reserve(s.size() * 3 / 4);
        uint32_t buf = 0;
        int bits = 0;
        for (char c : s) {
            int v = val(c);
            if (v < 0) continue;  // skip padding/whitespace
            buf = (buf << 6) | static_cast<uint32_t>(v);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<byte_t>((buf >> bits) & 0xFFu));
            }
        }
        return out;
    }

    // ── splitDots ─────────────────────────────────────────────────────────────

    [[nodiscard]] static std::vector<std::string> splitDots(std::string_view s) {
        std::vector<std::string> parts;
        std::size_t start = 0;
        for (std::size_t i = 0; i <= s.size(); ++i) {
            if (i == s.size() || s[i] == '.') {
                parts.emplace_back(s.substr(start, i - start));
                start = i + 1;
            }
        }
        return parts;
    }

    // ── constantTimeEqual ─────────────────────────────────────────────────────
    [[nodiscard]] static bool constantTimeEqual(
        const SecBytes& a, const SecBytes& b) noexcept
    {
        if (a.size() != b.size()) return false;
        volatile byte_t diff = 0;
        for (std::size_t i = 0; i < a.size(); ++i) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    // ── jsonEscape ────────────────────────────────────────────────────────────
    // Escape string for embedding in JSON (only needed for "sub" field)
    [[nodiscard]] static std::string jsonEscape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s) {
            if (c == '"')       out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else if (c < 0x20)  out += "\\u00" + toHex2(c);
            else                out += static_cast<char>(c);
        }
        return out;
    }

    [[nodiscard]] static std::string toHex2(unsigned char c) {
        constexpr char h[] = "0123456789abcdef";
        return { h[(c >> 4) & 0x0fu], h[c & 0x0fu] };
    }

    // ── clamp helper ──────────────────────────────────────────────────────────
    [[nodiscard]] static int clamp(int v, int lo, int hi) noexcept {
        return v < lo ? lo : (v > hi ? hi : v);
    }

    // ── Revoked JTI persistence ───────────────────────────────────────────────
    // Format: one hex JTI per line, no additional data

    void loadRevokedSet() {
        if (revokePersistPath_.empty()) return;
        std::ifstream f(revokePersistPath_);
        if (!f.is_open()) return;
        std::string line;
        std::lock_guard<std::mutex> lock(revokedMutex_);
        while (std::getline(f, line)) {
            // Validate before inserting — must be 32 hex chars
            if (line.size() == 32) {
                bool valid = true;
                for (char c : line)
                    if (!std::isxdigit(static_cast<unsigned char>(c)))
                        { valid = false; break; }
                if (valid) revokedJtis_.insert(line);
            }
        }
    }

    void persistRevokedSet() const {
        if (revokePersistPath_.empty()) return;
        std::ofstream f(revokePersistPath_, std::ios::trunc);
        if (!f.is_open()) return;
        std::lock_guard<std::mutex> lock(revokedMutex_);
        for (const auto& jti : revokedJtis_) f << jti << "\n";
    }
};

} // namespace SecFW
