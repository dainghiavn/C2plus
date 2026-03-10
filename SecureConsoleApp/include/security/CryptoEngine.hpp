#pragma once
// ============================================================
// CryptoEngine.hpp — FIXED v1.3
// FIX [BUG-12]: Check ALL EVP return values in encrypt/decrypt
// FIX [BUG-13]: Use unique_ptr for EVP_MD_CTX in sha256()
// Standards: FIPS 140-3, NIST SP 800-175B, CERT MSC50-CPP
// Dependencies: OpenSSL 3.x
// ============================================================
#include "SecureCore.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <memory>

namespace SecFW {

class CryptoEngine final {
public:
    static constexpr std::size_t AES_KEY_SIZE = 32;
    static constexpr std::size_t AES_IV_SIZE  = 12;
    static constexpr std::size_t AES_TAG_SIZE = 16;
    static constexpr std::size_t SHA256_SIZE  = 32;
    static constexpr std::size_t SALT_SIZE    = 32;

    // CSPRNG (FIPS 140-3)
    [[nodiscard]] static Result<SecBytes> randomBytes(std::size_t count) {
        if (RAND_status() != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "RAND not seeded");
        SecBytes buf(count);
        if (RAND_bytes(buf.data(), static_cast<int>(count)) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "RAND_bytes failed: " + getOpenSSLError());
        return Result<SecBytes>::Success(std::move(buf));
    }

    // AES-256-GCM Encrypt — output: IV(12)||TAG(16)||CIPHER
    // FIX [BUG-12]: All EVP calls now return-checked; errors propagate as Failure
    [[nodiscard]] static Result<SecBytes> encryptAESGCM(
        std::span<const byte_t> plaintext,
        std::span<const byte_t> key,
        std::span<const byte_t> aad = {})
    {
        if (key.size() != AES_KEY_SIZE)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "Invalid key size: expected 32, got " + std::to_string(key.size()));

        auto ivRes = randomBytes(AES_IV_SIZE);
        if (ivRes.fail()) return Result<SecBytes>::Failure(ivRes.status, ivRes.message);

        using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
        EvpCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "CTX alloc failed");

        // FIX [BUG-12]: Check each EVP call
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "EVP_EncryptInit_ex failed: " + getOpenSSLError());

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(AES_IV_SIZE), nullptr) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "GCM_SET_IVLEN failed");

        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                               key.data(), ivRes.value.data()) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "EVP_EncryptInit_ex (key/iv) failed: " + getOpenSSLError());

        if (!aad.empty()) {
            int len = 0;
            if (EVP_EncryptUpdate(ctx.get(), nullptr, &len,
                                  aad.data(), static_cast<int>(aad.size())) != 1)
                return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                    "AAD update failed");
        }

        // Ciphertext buffer = plaintext size (GCM is stream cipher, no padding)
        SecBytes ciphertext(plaintext.size());
        int outLen = 0;
        if (!plaintext.empty()) {
            if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outLen,
                                  plaintext.data(), static_cast<int>(plaintext.size())) != 1)
                return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                    "EVP_EncryptUpdate failed: " + getOpenSSLError());
        }

        int finalLen = 0;
        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outLen, &finalLen) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "EVP_EncryptFinal_ex failed: " + getOpenSSLError());

        SecBytes tag(AES_TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                                static_cast<int>(AES_TAG_SIZE), tag.data()) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "GCM_GET_TAG failed");

        // Build output: IV || TAG || CIPHER
        SecBytes output;
        output.reserve(AES_IV_SIZE + AES_TAG_SIZE + outLen + finalLen);
        output.insert(output.end(), ivRes.value.begin(), ivRes.value.end());
        output.insert(output.end(), tag.begin(), tag.end());
        output.insert(output.end(), ciphertext.begin(), ciphertext.begin() + outLen + finalLen);

        return Result<SecBytes>::Success(std::move(output));
    }

    // AES-256-GCM Decrypt
    // FIX [BUG-12]: Check ALL EVP calls
    [[nodiscard]] static Result<SecBytes> decryptAESGCM(
        std::span<const byte_t> cipherData,
        std::span<const byte_t> key,
        std::span<const byte_t> aad = {})
    {
        if (cipherData.size() < AES_IV_SIZE + AES_TAG_SIZE)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "Input too short");
        if (key.size() != AES_KEY_SIZE)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "Invalid key size");

        auto iv         = cipherData.subspan(0, AES_IV_SIZE);
        auto tag        = cipherData.subspan(AES_IV_SIZE, AES_TAG_SIZE);
        auto ciphertext = cipherData.subspan(AES_IV_SIZE + AES_TAG_SIZE);

        using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
        EvpCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "CTX alloc failed");

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "EVP_DecryptInit_ex failed");

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                                static_cast<int>(AES_IV_SIZE), nullptr) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "GCM_SET_IVLEN failed");

        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                               key.data(), iv.data()) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "EVP_DecryptInit_ex (key/iv) failed");

        if (!aad.empty()) {
            int len = 0;
            if (EVP_DecryptUpdate(ctx.get(), nullptr, &len,
                                  aad.data(), static_cast<int>(aad.size())) != 1)
                return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                    "AAD decrypt update failed");
        }

        SecBytes plaintext(ciphertext.size());
        int outLen = 0;
        if (!ciphertext.empty()) {
            if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outLen,
                                  ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
                return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                    "EVP_DecryptUpdate failed");
        }

        // Set expected tag BEFORE final
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                                static_cast<int>(AES_TAG_SIZE),
                                const_cast<byte_t*>(tag.data())) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "GCM_SET_TAG failed");

        int finalLen = 0;
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outLen, &finalLen) <= 0)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "Authentication tag mismatch — data may be tampered!");

        plaintext.resize(outLen + finalLen);
        return Result<SecBytes>::Success(std::move(plaintext));
    }

    // PBKDF2-HMAC-SHA256 (NIST SP 800-132), 600K iterations
    [[nodiscard]] static Result<SecBytes> hashPassword(
        std::string_view password,
        std::span<const byte_t> salt,
        int iterations = 600000)
    {
        if (salt.empty())
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "Empty salt");
        SecBytes hash(SHA256_SIZE);
        if (PKCS5_PBKDF2_HMAC(
                password.data(), static_cast<int>(password.size()),
                salt.data(), static_cast<int>(salt.size()),
                iterations, EVP_sha256(),
                static_cast<int>(SHA256_SIZE), hash.data()) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "PBKDF2 failed");
        return Result<SecBytes>::Success(std::move(hash));
    }

    // HMAC-SHA256
    [[nodiscard]] static Result<SecBytes> computeHMAC(
        std::span<const byte_t> message,
        std::span<const byte_t> key)
    {
        SecBytes mac(EVP_MAX_MD_SIZE);
        unsigned int macLen = 0;
        if (!HMAC(EVP_sha256(),
                  key.data(), static_cast<int>(key.size()),
                  message.data(), message.size(),
                  mac.data(), &macLen))
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "HMAC failed");
        mac.resize(macLen);
        return Result<SecBytes>::Success(std::move(mac));
    }

    // SHA-256
    // FIX [BUG-13]: Use unique_ptr for EVP_MD_CTX — no more leak on exception
    [[nodiscard]] static Result<SecBytes> sha256(std::span<const byte_t> data) {
        using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
        EvpMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "EVP_MD_CTX_new failed");

        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "DigestInit failed");
        if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "DigestUpdate failed");

        SecBytes hash(SHA256_SIZE);
        unsigned int len = 0;
        if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &len) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "DigestFinal failed");

        hash.resize(len);
        return Result<SecBytes>::Success(std::move(hash));
    }

    [[nodiscard]] static std::string toHex(std::span<const byte_t> bytes) {
        static const char hex[] = "0123456789abcdef";
        std::string result;
        result.reserve(bytes.size() * 2);
        for (byte_t b : bytes) {
            result += hex[b >> 4];
            result += hex[b & 0x0F];
        }
        return result;
    }

    // FIX: Validate hex input length is even; return empty on invalid input (no throw)
    [[nodiscard]] static SecBytes fromHex(const std::string& hex) {
        if (hex.size() % 2 != 0) return {}; // malformed hex
        SecBytes bytes;
        bytes.reserve(hex.size() / 2);
        for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
            char c1 = hex[i];
            char c2 = hex[i + 1];
            auto nib = [](char c) -> byte_t {
                if (c >= '0' && c <= '9') return static_cast<byte_t>(c - '0');
                if (c >= 'a' && c <= 'f') return static_cast<byte_t>(c - 'a' + 10);
                if (c >= 'A' && c <= 'F') return static_cast<byte_t>(c - 'A' + 10);
                return 0;
            };
            bytes.push_back(static_cast<byte_t>((nib(c1) << 4) | nib(c2)));
        }
        return bytes;
    }

private:
    static std::string getOpenSSLError() {
        char buf[256] = {};
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        return std::string(buf);
    }
};

} // namespace SecFW
