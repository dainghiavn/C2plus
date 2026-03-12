#pragma once
// ============================================================
// UserDatabase.hpp — FIXED v1.3
// FIX [BUG-10]: Cast to uint32_t/uint16_t BEFORE bit-shift
//               (signed int shift → UB on CERT INT34-C)
// FIX [BUG-11]: dirty_ flag consistency on failed save
// Standards: OWASP Password Storage CS, SEI CERT MSC41-C
// ============================================================
#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include "InputValidator.hpp"
#include <fstream>
#include <unordered_map>
#include <filesystem>
#include <sstream>
#include <optional>

namespace SecFW {

struct CredentialRecord {
    std::string userId;
    SecBytes    salt;
    SecBytes    hash;
    u32_t       roles { Roles::USER };
};

class UserDatabase final {
public:
    static constexpr int    PBKDF2_ITERATIONS = 600000;
    static constexpr std::size_t SALT_LEN     = 32;
    static constexpr uint32_t MAGIC  = 0x55444221; // "UDB!"
    static constexpr uint16_t VERSION = 0x0100;    // v1.0

    [[nodiscard]] Result<void> addUser(
        const std::string& userId,
        std::string_view   plaintextPassword,
        u32_t              roles = Roles::USER)
    {
        if (records_.count(userId))
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "User already exists: " + userId);

        auto saltRes = CryptoEngine::randomBytes(SALT_LEN);
        if (saltRes.fail()) return Result<void>::Failure(saltRes.status, saltRes.message);

        auto hashRes = CryptoEngine::hashPassword(plaintextPassword, saltRes.value, PBKDF2_ITERATIONS);
        if (hashRes.fail()) return Result<void>::Failure(hashRes.status, hashRes.message);

        records_[userId] = CredentialRecord{
            .userId = userId,
            .salt   = std::move(saltRes.value),
            .hash   = std::move(hashRes.value),
            .roles  = roles
        };
        dirty_ = true;
        return Result<void>::Success();
    }

    [[nodiscard]] Result<void> removeUser(const std::string& userId) {
        if (!records_.count(userId))
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "User not found: " + userId);
        records_.erase(userId);
        dirty_ = true;
        return Result<void>::Success();
    }

    // Constant-time verify (CERT MSC39-C)
    [[nodiscard]] Result<u32_t> verifyPassword(
        const std::string& userId,
        std::string_view   plaintextPassword) const
    {
        auto it = records_.find(userId);

        // FIX: Use a random per-instance dummy salt (generated in constructor)
        // instead of all-zeros, to mitigate timing analysis
        const SecBytes& salt = (it != records_.end()) ? it->second.salt : dummySalt_;

        auto hashRes = CryptoEngine::hashPassword(plaintextPassword, salt, PBKDF2_ITERATIONS);
        if (hashRes.fail())
            return Result<u32_t>::Failure(hashRes.status, "Hash error");

        if (it == records_.end())
            return Result<u32_t>::Failure(SecurityStatus::ERR_AUTH_FAILED, "Invalid credentials");

        const SecBytes& stored   = it->second.hash;
        const SecBytes& computed = hashRes.value;
        if (stored.size() != computed.size())
            return Result<u32_t>::Failure(SecurityStatus::ERR_AUTH_FAILED, "Invalid credentials");

        volatile int diff = 0;
        for (std::size_t i = 0; i < stored.size(); ++i)
            diff |= (stored[i] ^ computed[i]);

        if (diff != 0)
            return Result<u32_t>::Failure(SecurityStatus::ERR_AUTH_FAILED, "Invalid credentials");

        return Result<u32_t>::Success(it->second.roles);
    }

    [[nodiscard]] Result<void> saveTo(
        const std::string& filePath,
        std::span<const byte_t> masterKey) const
    {
        // Build plaintext
        std::ostringstream oss;
        for (const auto& [uid, rec] : records_)
            oss << uid << "|"
                << CryptoEngine::toHex(rec.salt) << "|"
                << CryptoEngine::toHex(rec.hash) << "|"
                << rec.roles << "\n";

        std::string plain = oss.str();
        SecBytes plainBytes(plain.begin(), plain.end());

        // Encrypt
        auto encRes = CryptoEngine::encryptAESGCM(plainBytes, masterKey);
        if (encRes.fail()) return Result<void>::Failure(encRes.status, encRes.message);

        // Prepare header: MAGIC(4) + VERSION(2) + reserved(2)
        SecBytes header;
        header.reserve(8);
        // FIX [BUG-10]: Use uint32_t for all bit operations before narrowing cast
        for (int i = 0; i < 4; ++i)
            header.push_back(static_cast<byte_t>((static_cast<uint32_t>(MAGIC) >> (i * 8)) & 0xFFu));
        for (int i = 0; i < 2; ++i)
            header.push_back(static_cast<byte_t>((static_cast<uint32_t>(VERSION) >> (i * 8)) & 0xFFu));
        header.push_back(0); header.push_back(0); // reserved

        // Write to temp file
        std::string tmpPath = filePath + ".tmp";
        {
            std::ofstream file(tmpPath, std::ios::binary | std::ios::trunc);
            if (!file.is_open())
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "Cannot write temp file: " + tmpPath);

            file.write(reinterpret_cast<const char*>(header.data()),
                       static_cast<std::streamsize>(header.size()));
            file.write(reinterpret_cast<const char*>(encRes.value.data()),
                       static_cast<std::streamsize>(encRes.value.size()));

            // Explicit flush + check before rename
            file.flush();
            if (!file.good()) {
                std::filesystem::remove(tmpPath);
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "Write error on temp file: " + tmpPath);
            }
        } // file closed here (RAII)

        // Rename to final
        std::error_code ec;
        std::filesystem::rename(tmpPath, filePath, ec);
        if (ec) {
            std::filesystem::remove(tmpPath, ec); // cleanup temp on failure
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Rename failed: " + ec.message());
        }

#ifndef _WIN32
        namespace fs = std::filesystem;
        fs::permissions(filePath,
            fs::perms::owner_read | fs::perms::owner_write,
            fs::perm_options::replace);
#endif
        // FIX [BUG-11]: Only clear dirty after successful atomic save
        dirty_ = false;
        return Result<void>::Success();
    }

    [[nodiscard]] Result<void> loadFrom(
        const std::string& filePath,
        std::span<const byte_t> masterKey)
    {
        namespace fs = std::filesystem;
        if (!fs::exists(filePath))
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "UserDB not found: " + filePath);

        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open())
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Cannot open UserDB: " + filePath);

        // Read header
        SecBytes header(8);
        file.read(reinterpret_cast<char*>(header.data()), 8);
        if (file.gcount() != 8)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID, "File too short");

        // FIX [BUG-10]: Explicit uint32_t cast BEFORE shift to prevent signed UB
        uint32_t magic = 0;
        for (int i = 0; i < 4; ++i)
            magic |= (static_cast<uint32_t>(header[i]) << (i * 8));
        if (magic != MAGIC)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID, "Invalid file format");

        uint16_t ver = 0;
        for (int i = 0; i < 2; ++i)
            ver = static_cast<uint16_t>(ver | (static_cast<uint16_t>(header[4 + i]) << (i * 8)));
        if (ver != VERSION)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Unsupported version: " + std::to_string(ver));

        // Read encrypted data
        SecBytes encrypted((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());

        auto decRes = CryptoEngine::decryptAESGCM(encrypted, masterKey);
        if (decRes.fail())
            return Result<void>::Failure(decRes.status,
                "Decrypt failed — wrong key or tampered file");

        std::string content(decRes.value.begin(), decRes.value.end());
        std::istringstream iss(content);
        std::string line;
        int lineNum = 0;
        while (std::getline(iss, line)) {
            ++lineNum;
            if (line.empty() || line[0] == '#') continue;
            auto parts = splitLine(line, '|');
            if (parts.size() != 4)
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "Malformed UserDB at line " + std::to_string(lineNum));

            CredentialRecord rec;
            rec.userId = parts[0];
            rec.salt   = CryptoEngine::fromHex(parts[1]);
            rec.hash   = CryptoEngine::fromHex(parts[2]);
            auto rolesRes = InputValidator::parseInteger<u32_t>(parts[3], 0, 0xFFFF);
            if (rolesRes.fail())
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "Invalid roles at line " + std::to_string(lineNum));
            rec.roles = rolesRes.value;
            records_[rec.userId] = std::move(rec);
        }
        dirty_ = false;
        return Result<void>::Success();
    }

    [[nodiscard]] bool        isDirty()    const noexcept { return dirty_; }
    [[nodiscard]] std::size_t userCount()  const noexcept { return records_.size(); }
    [[nodiscard]] bool        empty()      const noexcept { return records_.empty(); }
    void                      clearDirty()       noexcept { dirty_ = false; }

    [[nodiscard]] bool hasUser(const std::string& userId) const noexcept {
        return records_.count(userId) > 0;
    }

    // Iterate all users — callback receives (userId, roleFlags).
    // Does NOT expose password hashes or salts.
    template <typename Fn>
    void forEachUser(Fn&& fn) const {
        for (const auto& [uid, rec] : records_)
            fn(uid, rec.roles);
    }

private:
    static std::vector<std::string> splitLine(const std::string& s, char delim) {
        std::vector<std::string> parts;
        std::istringstream iss(s);
        std::string token;
        while (std::getline(iss, token, delim)) parts.push_back(token);
        return parts;
    }

    // FIX: Random dummy salt initialized at construction (better timing side-channel resistance)
    SecBytes initDummySalt() const {
        auto res = CryptoEngine::randomBytes(SALT_LEN);
        if (res.ok()) return res.value;
        return SecBytes(SALT_LEN, 0xA5); // fallback if CSPRNG fails (shouldn't happen)
    }

    std::unordered_map<std::string, CredentialRecord> records_;
    mutable bool     dirty_ { false };
    const SecBytes   dummySalt_ { initDummySalt() };
};

} // namespace SecFW
