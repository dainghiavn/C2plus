#pragma once
// ============================================================
// CryptoEngine.hpp
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
        SecBytes buf(count);
        if (RAND_bytes(buf.data(), static_cast<int>(count)) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "RAND_bytes failed: " + getOpenSSLError());
        return Result<SecBytes>::Success(std::move(buf));
    }

    // AES-256-GCM Encrypt — output: IV(12)||TAG(16)||CIPHER
    [[nodiscard]] static Result<SecBytes> encryptAESGCM(
        std::span<const byte_t> plaintext,
        std::span<const byte_t> key,
        std::span<const byte_t> aad = {})
    {
        if (key.size() != AES_KEY_SIZE)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "Invalid key size");

        auto ivRes = randomBytes(AES_IV_SIZE);
        if (ivRes.fail()) return Result<SecBytes>::Failure(ivRes.status, ivRes.message);

        SecBytes output;
        output.reserve(AES_IV_SIZE + AES_TAG_SIZE + plaintext.size());
        output.insert(output.end(), ivRes.value.begin(), ivRes.value.end());

        using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
        EvpCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "CTX alloc failed");

        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr);
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), ivRes.value.data());

        if (!aad.empty()) {
            int len = 0;
            EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size()));
        }

        SecBytes ciphertext(plaintext.size() + 16);
        int outLen = 0;
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outLen,
            plaintext.data(), static_cast<int>(plaintext.size()));

        int finalLen = 0;
        EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outLen, &finalLen);

        SecBytes tag(AES_TAG_SIZE);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag.data());

        output.insert(output.end(), tag.begin(), tag.end());
        output.insert(output.end(), ciphertext.begin(), ciphertext.begin() + outLen + finalLen);

        return Result<SecBytes>::Success(std::move(output));
    }

    // AES-256-GCM Decrypt
    [[nodiscard]] static Result<SecBytes> decryptAESGCM(
        std::span<const byte_t> cipherData,
        std::span<const byte_t> key,
        std::span<const byte_t> aad = {})
    {
        if (cipherData.size() < AES_IV_SIZE + AES_TAG_SIZE)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL, "Input too short");

        auto iv         = cipherData.subspan(0, AES_IV_SIZE);
        auto tag        = cipherData.subspan(AES_IV_SIZE, AES_TAG_SIZE);
        auto ciphertext = cipherData.subspan(AES_IV_SIZE + AES_TAG_SIZE);

        using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
        EvpCtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr);
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data());

        if (!aad.empty()) {
            int len = 0;
            EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size()));
        }

        SecBytes plaintext(ciphertext.size());
        int outLen = 0;
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outLen,
            ciphertext.data(), static_cast<int>(ciphertext.size()));

        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
            AES_TAG_SIZE, const_cast<byte_t*>(tag.data()));

        int finalLen = 0;
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outLen, &finalLen) <= 0)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "Authentication tag mismatch - data tampered!");

        plaintext.resize(outLen + finalLen);
        return Result<SecBytes>::Success(std::move(plaintext));
    }

    // PBKDF2-HMAC-SHA256 (NIST SP 800-132), 600K iterations
    [[nodiscard]] static Result<SecBytes> hashPassword(
        std::string_view password,
        std::span<const byte_t> salt,
        int iterations = 600000)
    {
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

    // SHA-256 of a buffer
    [[nodiscard]] static Result<SecBytes> sha256(std::span<const byte_t> data) {
        SecBytes hash(SHA256_SIZE);
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        unsigned int len = 0;
        EVP_DigestFinal_ex(ctx, hash.data(), &len);
        EVP_MD_CTX_free(ctx);
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

    [[nodiscard]] static SecBytes fromHex(const std::string& hex) {
        SecBytes bytes;
        bytes.reserve(hex.size() / 2);
        for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
            bytes.push_back(static_cast<byte_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
        return bytes;
    }

private:
    static std::string getOpenSSLError() {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        return std::string(buf);
    }
};

} // namespace SecFW
