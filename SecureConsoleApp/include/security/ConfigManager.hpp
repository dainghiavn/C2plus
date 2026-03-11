#pragma once
// ============================================================
// ConfigManager.hpp — v1.3
// Encrypted, HMAC-verified configuration store.
//
// File format (binary):
//   [4B magic] [4B version] [4B entry_count]
//   for each entry:
//     [2B key_len] [key_bytes]
//     [2B val_len] [val_bytes]
//   then the entire key+value section is AES-256-GCM encrypted:
//     IV (12B) || TAG (16B) || CIPHERTEXT
//
// Integrity:
//   An HMAC-SHA256 of the whole encrypted file is appended (32B).
//   loadFrom() verifies the HMAC before decrypting.
//
// In-memory:
//   Decrypted values are held in SecureString instances so they are
//   zeroed on destruction.  The encryption key is not stored in the
//   ConfigManager instance after load.
//
// Standards:
//   NIST SP 800-38D (AES-GCM)
//   OWASP ASVS V14.4 (Secrets Management)
//   CERT MSC41-C     (no secrets in plain config files)
// ============================================================

#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include "InputValidator.hpp"
#include <unordered_map>
#include <string>
#include <string_view>
#include <optional>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>

namespace SecFW {

class ConfigManager final {
public:
    // Magic / version header
    static constexpr uint32_t MAGIC   = 0x43464757u; // "WCFG"
    static constexpr uint32_t VERSION = 0x00010003u; // 1.3

    ConfigManager()  = default;
    ~ConfigManager() { clear(); }

    // Non-copyable — contains sensitive in-memory values
    ConfigManager(const ConfigManager&)            = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    ConfigManager(ConfigManager&&)                 = default;
    ConfigManager& operator=(ConfigManager&&)      = default;

    // ── set / get ─────────────────────────────────────────────────────────────
    //
    // Keys are plain strings (non-sensitive).
    // Values are SecureString so secrets are zeroed on clear() / destruction.

    // BUG-19 FIX: return Result<void> instead of throwing — consistent with framework
    [[nodiscard]] Result<void> set(std::string_view key, std::string_view value) {
        auto kv = validateKey(key);
        if (kv.fail()) return kv;
        store_[std::string(key)] = SecureString(value);
        return Result<void>::Success();
    }

    [[nodiscard]] std::optional<std::string_view> get(std::string_view key) const {
        auto it = store_.find(std::string(key));
        if (it == store_.end()) return std::nullopt;
        return it->second.view();
    }

    // Convenience: get with a fallback default (non-sensitive values only)
    [[nodiscard]] std::string getOr(std::string_view key,
                                    std::string_view fallback) const {
        auto v = get(key);
        return v ? std::string(*v) : std::string(fallback);
    }

    [[nodiscard]] bool contains(std::string_view key) const {
        return store_.count(std::string(key)) > 0;
    }

    void remove(std::string_view key) { store_.erase(std::string(key)); }

    // Zero and clear all entries
    void clear() noexcept { store_.clear(); }

    // ── saveTo ────────────────────────────────────────────────────────────────
    //
    // Serialise + AES-GCM encrypt + HMAC and write to `path`.
    // `encKey` must be exactly 32 bytes (AES-256).
    // `hmacKey` must be exactly 32 bytes.

    [[nodiscard]] Result<void> saveTo(
        const std::string&          path,
        std::span<const byte_t>     encKey,
        std::span<const byte_t>     hmacKey) const
    {
        if (encKey.size() != 32 || hmacKey.size() != 32)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager::saveTo: key size must be 32 bytes");

        auto pathCheck = InputValidator::isValidPath(path);
        if (pathCheck.fail()) return pathCheck;

        // ── Serialise ──────────────────────────────────────────────────────
        SecBytes plain;
        writeU32(plain, MAGIC);
        writeU32(plain, VERSION);
        writeU32(plain, static_cast<uint32_t>(store_.size()));

        for (const auto& [k, v] : store_) {
            if (k.size() > 0xFFFFu || v.size() > 0xFFFFu)
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "key or value exceeds 65535 bytes");

            writeU16(plain, static_cast<uint16_t>(k.size()));
            plain.insert(plain.end(),
                reinterpret_cast<const byte_t*>(k.data()),
                reinterpret_cast<const byte_t*>(k.data()) + k.size());

            writeU16(plain, static_cast<uint16_t>(v.size()));
            plain.insert(plain.end(),
                reinterpret_cast<const byte_t*>(v.view().data()),
                reinterpret_cast<const byte_t*>(v.view().data()) + v.size());
        }

        // ── Encrypt ────────────────────────────────────────────────────────
        auto encRes = CryptoEngine::encryptAESGCM(plain, encKey);
        if (encRes.fail()) return Result<void>::Failure(encRes.status, encRes.message);

        // ── HMAC over ciphertext ───────────────────────────────────────────
        auto hmacRes = CryptoEngine::computeHMAC(encRes.value, hmacKey);
        if (hmacRes.fail()) return Result<void>::Failure(hmacRes.status, hmacRes.message);

        // ── Write file ─────────────────────────────────────────────────────
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager: cannot open '" + path + "' for writing");

        out.write(reinterpret_cast<const char*>(encRes.value.data()),
                  static_cast<std::streamsize>(encRes.value.size()));
        out.write(reinterpret_cast<const char*>(hmacRes.value.data()),
                  static_cast<std::streamsize>(hmacRes.value.size()));

        if (!out)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager: write error on '" + path + "'");

        return Result<void>::Success();
    }

    // ── loadFrom ─────────────────────────────────────────────────────────────
    //
    // Load, verify HMAC, decrypt and deserialise from `path`.
    // Replaces any existing in-memory entries on success.
    // Leaves existing entries unchanged on failure.

    [[nodiscard]] Result<void> loadFrom(
        const std::string&          path,
        std::span<const byte_t>     encKey,
        std::span<const byte_t>     hmacKey)
    {
        if (encKey.size() != 32 || hmacKey.size() != 32)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager::loadFrom: key size must be 32 bytes");

        auto pathCheck = InputValidator::isValidPath(path);
        if (pathCheck.fail()) return pathCheck;

        // ── Read whole file ────────────────────────────────────────────────
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager: cannot open '" + path + "'");

        auto fileSize = static_cast<std::size_t>(in.tellg());
        if (fileSize < 32 + CryptoEngine::AES_IV_SIZE + CryptoEngine::AES_TAG_SIZE + 4)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager: file too small");

        in.seekg(0);
        SecBytes buf(fileSize);
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(fileSize));
        if (!in)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager: read error");

        // ── Split: ciphertext | HMAC (last 32 bytes) ──────────────────────
        constexpr std::size_t HMAC_SIZE = 32;
        std::span<const byte_t> storedHmac(buf.data() + fileSize - HMAC_SIZE, HMAC_SIZE);
        std::span<const byte_t> cipherBlob(buf.data(), fileSize - HMAC_SIZE);

        // ── Verify HMAC ────────────────────────────────────────────────────
        auto hmacRes = CryptoEngine::computeHMAC(cipherBlob, hmacKey);
        if (hmacRes.fail()) return Result<void>::Failure(hmacRes.status, hmacRes.message);

        // Constant-time comparison (CERT MSC39-C, timing side-channel)
        if (hmacRes.value.size() != HMAC_SIZE ||
            !constantTimeEqual(hmacRes.value, storedHmac))
            return Result<void>::Failure(SecurityStatus::ERR_TAMPER_DETECTED,
                "ConfigManager: HMAC verification failed — file may be tampered");

        // ── Decrypt ────────────────────────────────────────────────────────
        auto decRes = CryptoEngine::decryptAESGCM(cipherBlob, encKey);
        if (decRes.fail()) return Result<void>::Failure(decRes.status, decRes.message);

        // ── Deserialise ────────────────────────────────────────────────────
        return deserialise(decRes.value);
    }

private:
    std::unordered_map<std::string, SecureString> store_;

    // ── Serialisation helpers ──────────────────────────────────────────────

    static void writeU32(SecBytes& buf, uint32_t v) {
        for (int i = 0; i < 4; ++i)
            buf.push_back(static_cast<byte_t>((static_cast<uint32_t>(v) >> (i * 8)) & 0xFFu));
    }

    static void writeU16(SecBytes& buf, uint16_t v) {
        buf.push_back(static_cast<byte_t>(v & 0xFFu));
        buf.push_back(static_cast<byte_t>((v >> 8) & 0xFFu));
    }

    [[nodiscard]] static uint32_t readU32(const SecBytes& buf, std::size_t& pos) {
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v |= static_cast<uint32_t>(buf[pos + i]) << (i * 8);
        pos += 4;
        return v;
    }

    [[nodiscard]] static uint16_t readU16(const SecBytes& buf, std::size_t& pos) {
        uint16_t v = static_cast<uint16_t>(buf[pos]) |
                     static_cast<uint16_t>(static_cast<uint16_t>(buf[pos + 1]) << 8);
        pos += 2;
        return v;
    }

    [[nodiscard]] Result<void> deserialise(const SecBytes& plain) {
        if (plain.size() < 12)  // magic + version + count
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager: plaintext too short");

        std::size_t pos = 0;
        uint32_t magic   = readU32(plain, pos);
        uint32_t version = readU32(plain, pos);
        uint32_t count   = readU32(plain, pos);

        if (magic != MAGIC)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager: bad magic number");

        if ((version & 0xFFFF0000u) != (VERSION & 0xFFFF0000u))
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager: incompatible major version " +
                std::to_string(version >> 16));

        if (count > 65535u)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager: entry count too large");

        std::unordered_map<std::string, SecureString> tmp;
        tmp.reserve(count);

        for (uint32_t i = 0; i < count; ++i) {
            if (pos + 2 > plain.size())
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "ConfigManager: truncated at entry " + std::to_string(i));

            uint16_t kLen = readU16(plain, pos);
            if (pos + kLen > plain.size())
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "ConfigManager: key overrun at entry " + std::to_string(i));
            std::string key(reinterpret_cast<const char*>(&plain[pos]), kLen);
            pos += kLen;

            // Validate key characters before inserting
            auto kv = InputValidator::validate(key, {.minLen=1,.maxLen=256}, "config-key");
            if (kv.fail()) return kv;

            if (pos + 2 > plain.size())
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "ConfigManager: truncated before value at entry " + std::to_string(i));

            uint16_t vLen = readU16(plain, pos);
            if (pos + vLen > plain.size())
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "ConfigManager: value overrun at entry " + std::to_string(i));
            std::string_view val(reinterpret_cast<const char*>(&plain[pos]), vLen);
            pos += vLen;

            tmp.emplace(std::move(key), SecureString(val));
        }

        // Only replace store_ after full successful parse
        store_ = std::move(tmp);
        return Result<void>::Success();
    }

    // ── constantTimeEqual ─────────────────────────────────────────────────────
    //
    // CERT MSC39-C: timing-safe byte comparison to prevent HMAC oracle.

    [[nodiscard]] static bool constantTimeEqual(
        std::span<const byte_t> a,
        std::span<const byte_t> b) noexcept
    {
        if (a.size() != b.size()) return false;
        volatile byte_t diff = 0;
        for (std::size_t i = 0; i < a.size(); ++i)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    // BUG-19 FIX: return Result<void> — no exceptions in security paths (CERT ERR50-CPP)
    [[nodiscard]] static Result<void> validateKey(std::string_view key) {
        if (key.empty() || key.size() > 256)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "ConfigManager: key length invalid (1-256 chars required)");
        for (char c : key)
            if (!std::isprint(static_cast<unsigned char>(c)))
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "ConfigManager: non-printable character in key");
        return Result<void>::Success();
    }
};

} // namespace SecFW
