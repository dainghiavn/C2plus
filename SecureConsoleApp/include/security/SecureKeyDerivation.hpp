#pragma once
// ============================================================
// SecureKeyDerivation.hpp — NEW FEATURE v1.3
//
// Derive multiple purpose-specific keys from a single master key
// using HKDF (RFC 5869) with domain separation.
//
// This prevents key reuse: instead of using masterKey for both
// database encryption AND audit log HMAC, derive separate keys:
//
//   auto dbKey  = KeyDerivation::deriveKey(masterKey, "db-encryption");
//   auto logKey = KeyDerivation::deriveKey(masterKey, "audit-hmac");
//   auto totpKey = KeyDerivation::deriveKey(masterKey, "totp-storage");
//
// Standards: NIST SP 800-108, RFC 5869 (HKDF)
// ============================================================
#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string>

namespace SecFW {

class KeyDerivation final {
public:
    // ── HKDF-SHA256: derive purpose-specific 32-byte key ──
    // context: human-readable label, e.g. "db-encryption-v1"
    // salt:    optional random bytes (leave empty to use default)
    [[nodiscard]] static Result<SecBytes> deriveKey(
        std::span<const byte_t> masterKey,
        std::string_view        context,
        std::size_t             outputLen = CryptoEngine::AES_KEY_SIZE,
        std::span<const byte_t> salt = {})
    {
        if (masterKey.empty())
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "Master key cannot be empty");
        if (context.empty())
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "Context/label cannot be empty");
        if (outputLen < 16 || outputLen > 64)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "Output length must be 16-64 bytes");

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        return hkdfOpenSSL3(masterKey, context, outputLen, salt);
#else
        return hkdfFallback(masterKey, context, outputLen, salt);
#endif
    }

    // ── Derive all application keys from one master key ──
    // Returns a bundle of domain-separated keys
    struct KeyBundle {
        SecBytes dbEncryptionKey;    // AES-256-GCM for UserDatabase
        SecBytes auditHmacKey;       // HMAC-SHA256 for SignedAuditLog
        SecBytes totpStorageKey;     // AES-256-GCM for TOTP secret storage
        SecBytes configEncryptKey;   // AES-256-GCM for ConfigManager
        SecBytes sessionHmacKey;     // HMAC for session tokens
    };

    [[nodiscard]] static Result<KeyBundle> deriveAll(
        std::span<const byte_t> masterKey)
    {
        KeyBundle bundle;

        auto derive = [&](std::string_view ctx) -> Result<SecBytes> {
            return deriveKey(masterKey, ctx);
        };

        auto r1 = derive("secfw-db-encryption-v1");
        if (r1.fail()) return Result<KeyBundle>::Failure(r1.status, r1.message);
        bundle.dbEncryptionKey = std::move(r1.value);

        auto r2 = derive("secfw-audit-hmac-v1");
        if (r2.fail()) return Result<KeyBundle>::Failure(r2.status, r2.message);
        bundle.auditHmacKey = std::move(r2.value);

        auto r3 = derive("secfw-totp-storage-v1");
        if (r3.fail()) return Result<KeyBundle>::Failure(r3.status, r3.message);
        bundle.totpStorageKey = std::move(r3.value);

        auto r4 = derive("secfw-config-encryption-v1");
        if (r4.fail()) return Result<KeyBundle>::Failure(r4.status, r4.message);
        bundle.configEncryptKey = std::move(r4.value);

        auto r5 = derive("secfw-session-hmac-v1");
        if (r5.fail()) return Result<KeyBundle>::Failure(r5.status, r5.message);
        bundle.sessionHmacKey = std::move(r5.value);

        return Result<KeyBundle>::Success(std::move(bundle));
    }

private:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    [[nodiscard]] static Result<SecBytes> hkdfOpenSSL3(
        std::span<const byte_t> masterKey,
        std::string_view        context,
        std::size_t             outputLen,
        std::span<const byte_t> salt)
    {
        using EvpKdfPtr    = std::unique_ptr<EVP_KDF,     decltype(&EVP_KDF_free)>;
        using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

        EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free);
        if (!kdf)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "EVP_KDF_fetch HKDF failed");

        EvpKdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
        if (!ctx)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "EVP_KDF_CTX_new failed");

        // Default salt: zeros
        SecBytes saltBytes;
        if (salt.empty()) {
            saltBytes.assign(32, 0);
        } else {
            saltBytes.assign(salt.begin(), salt.end());
        }

        const char* digest_name = "SHA256";
        OSSL_PARAM params[6];
        int p = 0;
        params[p++] = OSSL_PARAM_construct_utf8_string(
            "digest", const_cast<char*>(digest_name), 0);
        params[p++] = OSSL_PARAM_construct_octet_string(
            "key",
            const_cast<byte_t*>(masterKey.data()), masterKey.size());
        params[p++] = OSSL_PARAM_construct_octet_string(
            "salt", saltBytes.data(), saltBytes.size());
        params[p++] = OSSL_PARAM_construct_octet_string(
            "info",
            const_cast<char*>(context.data()), context.size());
        params[p++] = OSSL_PARAM_construct_end();

        SecBytes output(outputLen);
        if (EVP_KDF_derive(ctx.get(), output.data(), outputLen, params) != 1)
            return Result<SecBytes>::Failure(SecurityStatus::ERR_CRYPTO_FAIL,
                "HKDF derivation failed");

        return Result<SecBytes>::Success(std::move(output));
    }
#else
    // HKDF fallback using HMAC-SHA256 (RFC 5869)
    [[nodiscard]] static Result<SecBytes> hkdfFallback(
        std::span<const byte_t> masterKey,
        std::string_view        context,
        std::size_t             outputLen,
        std::span<const byte_t> salt)
    {
        // Step 1: Extract — PRK = HMAC-SHA256(salt, IKM)
        SecBytes saltBytes;
        if (salt.empty()) saltBytes.assign(32, 0);
        else saltBytes.assign(salt.begin(), salt.end());

        auto prk = CryptoEngine::computeHMAC(masterKey, saltBytes);
        if (prk.fail()) return Result<SecBytes>::Failure(prk.status, prk.message);

        // Step 2: Expand — T(i) = HMAC(PRK, T(i-1) || info || i)
        SecBytes output;
        SecBytes prev;
        u32_t i = 1;
        while (output.size() < outputLen) {
            std::vector<byte_t> msg;
            msg.insert(msg.end(), prev.begin(), prev.end());
            msg.insert(msg.end(), context.begin(), context.end());
            msg.push_back(static_cast<byte_t>(i++));

            auto ti = CryptoEngine::computeHMAC(msg, prk.value);
            if (ti.fail()) return Result<SecBytes>::Failure(ti.status, ti.message);

            output.insert(output.end(), ti.value.begin(), ti.value.end());
            prev = ti.value;
        }
        output.resize(outputLen);
        return Result<SecBytes>::Success(std::move(output));
    }
#endif
};

} // namespace SecFW
