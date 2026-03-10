#pragma once
// ============================================================
// SecureTOTP.hpp — NEW FEATURE v1.3
// Time-based One-Time Password (TOTP) — RFC 6238
// Compatible with Google Authenticator, Authy, etc.
//
// Usage:
//   auto secret = SecureTOTP::generateSecret();
//   std::string qr_uri = SecureTOTP::buildOtpAuthUri("MyApp", "user@example.com", secret);
//   // Show QR code for this URI to user
//   bool ok = SecureTOTP::verify(inputCode, secret);
//
// Standards: RFC 6238, RFC 4226, OWASP MFA CS
// ============================================================
#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include <openssl/hmac.h>
#include <chrono>
#include <cstring>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <string>

namespace SecFW {

class SecureTOTP final {
public:
    // TOTP parameters (NIST SP 800-63B recommended)
    static constexpr std::size_t SECRET_LEN     = 20;   // 160-bit secret
    static constexpr int         DIGITS          = 6;    // 6-digit code
    static constexpr int         STEP_SECONDS    = 30;   // 30s window
    static constexpr int         WINDOW_SIZE     = 1;    // ±1 window tolerance (90s total)

    // ── Generate a new random TOTP secret ──
    [[nodiscard]] static Result<SecBytes> generateSecret() {
        return CryptoEngine::randomBytes(SECRET_LEN);
    }

    // ── Compute current TOTP code ──
    [[nodiscard]] static Result<std::string> generate(
        std::span<const byte_t> secret,
        std::time_t             atTime = 0)
    {
        if (atTime == 0)
            atTime = std::chrono::system_clock::to_time_t(
                         std::chrono::system_clock::now());

        uint64_t counter = static_cast<uint64_t>(atTime) / STEP_SECONDS;
        return hotp(secret, counter);
    }

    // ── Verify a 6-digit code (with window tolerance) ──
    [[nodiscard]] static Result<bool> verify(
        std::string_view        code,
        std::span<const byte_t> secret,
        std::time_t             atTime = 0)
    {
        if (code.size() != static_cast<std::size_t>(DIGITS))
            return Result<bool>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "TOTP code must be " + std::to_string(DIGITS) + " digits");

        for (char c : code)
            if (!std::isdigit(static_cast<unsigned char>(c)))
                return Result<bool>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "TOTP code must be numeric");

        if (atTime == 0)
            atTime = std::chrono::system_clock::to_time_t(
                         std::chrono::system_clock::now());

        uint64_t counter = static_cast<uint64_t>(atTime) / STEP_SECONDS;

        // Check current window ± WINDOW_SIZE
        for (int delta = -WINDOW_SIZE; delta <= WINDOW_SIZE; ++delta) {
            uint64_t c = static_cast<uint64_t>(
                static_cast<int64_t>(counter) + delta);
            auto res = hotp(secret, c);
            if (res.fail()) return Result<bool>::Failure(res.status, res.message);

            // Constant-time string comparison
            if (constTimeEqual(res.value, std::string(code)))
                return Result<bool>::Success(true);
        }
        return Result<bool>::Success(false);
    }

    // ── Base32 encode (for QR code display) ──
    [[nodiscard]] static std::string base32Encode(std::span<const byte_t> data) {
        static const char* B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string result;
        result.reserve((data.size() * 8 + 4) / 5);

        int buffer = 0, bitsLeft = 0;
        for (byte_t b : data) {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                result += B32[(buffer >> bitsLeft) & 0x1F];
            }
        }
        if (bitsLeft > 0) {
            buffer <<= (5 - bitsLeft);
            result += B32[buffer & 0x1F];
        }
        // Padding
        while (result.size() % 8 != 0) result += '=';
        return result;
    }

    // ── Build otpauth:// URI for QR code generators ──
    [[nodiscard]] static std::string buildOtpAuthUri(
        std::string_view        issuer,
        std::string_view        accountName,
        std::span<const byte_t> secret)
    {
        std::string secretB32 = base32Encode(secret);
        std::ostringstream oss;
        oss << "otpauth://totp/"
            << urlEncode(std::string(issuer)) << ":"
            << urlEncode(std::string(accountName))
            << "?secret=" << secretB32
            << "&issuer=" << urlEncode(std::string(issuer))
            << "&algorithm=SHA1"
            << "&digits=" << DIGITS
            << "&period=" << STEP_SECONDS;
        return oss.str();
    }

    // ── Format secret for manual entry (groups of 4) ──
    [[nodiscard]] static std::string formatSecretForDisplay(
        std::span<const byte_t> secret)
    {
        std::string b32 = base32Encode(secret);
        // Remove padding
        while (!b32.empty() && b32.back() == '=') b32.pop_back();
        // Group into blocks of 4
        std::string formatted;
        for (std::size_t i = 0; i < b32.size(); ++i) {
            if (i > 0 && i % 4 == 0) formatted += ' ';
            formatted += b32[i];
        }
        return formatted;
    }

private:
    // HOTP (RFC 4226): HMAC-SHA1 based OTP
    [[nodiscard]] static Result<std::string> hotp(
        std::span<const byte_t> secret,
        uint64_t counter)
    {
        // Counter in big-endian
        byte_t counterBuf[8];
        for (int i = 7; i >= 0; --i) {
            counterBuf[i] = static_cast<byte_t>(counter & 0xFF);
            counter >>= 8;
        }

        // HMAC-SHA1 (RFC 4226 mandates SHA1 for base HOTP)
        unsigned char mac[20];
        unsigned int macLen = 0;
        if (!HMAC(EVP_sha1(),
                  secret.data(), static_cast<int>(secret.size()),
                  counterBuf, 8,
                  mac, &macLen) || macLen != 20)
            return Result<std::string>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "TOTP HMAC-SHA1 failed");

        // Dynamic truncation (RFC 4226 §5.4)
        int offset = mac[19] & 0x0F;
        uint32_t binCode = ((mac[offset]     & 0x7F) << 24) |
                           ((mac[offset + 1] & 0xFF) << 16) |
                           ((mac[offset + 2] & 0xFF) <<  8) |
                           ((mac[offset + 3] & 0xFF));

        uint32_t otp = binCode % static_cast<uint32_t>(std::pow(10, DIGITS));

        // Zero-pad to DIGITS
        std::ostringstream oss;
        oss << std::setw(DIGITS) << std::setfill('0') << otp;
        return Result<std::string>::Success(oss.str());
    }

    // Constant-time string comparison (prevent timing attacks on OTP verification)
    static bool constTimeEqual(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        volatile int diff = 0;
        for (std::size_t i = 0; i < a.size(); ++i)
            diff |= (a[i] ^ b[i]);
        return diff == 0;
    }

    static std::string urlEncode(const std::string& s) {
        std::ostringstream oss;
        for (unsigned char c : s) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                oss << c;
            else
                oss << '%' << std::uppercase << std::hex
                    << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        return oss.str();
    }
};

} // namespace SecFW
