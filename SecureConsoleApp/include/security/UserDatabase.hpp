#pragma once
// ============================================================
// UserDatabase.hpp — FIXED: file header, temp file, version check
// No hardcoded credentials. PBKDF2-hashed storage.
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
    static constexpr uint32_t MAGIC = 0x55444221; // "UDB!"
    static constexpr uint16_t VERSION = 0x0100;   // v1.0

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
        SecBytes dummySalt(SALT_LEN, 0x00);
        const SecBytes& salt = (it != records_.end()) ? it->second.salt : dummySalt;

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
        for (int i = 0; i < 4; ++i) header.push_back(static_cast<byte_t>((MAGIC >> (i*8)) & 0xFF));
        for (int i = 0; i < 2; ++i) header.push_back(static_cast<byte_t>((VERSION >> (i*8)) & 0xFF));
        header.push_back(0); header.push_back(0); // reserved

        // Write to temp file
        std::string tmpPath = filePath + ".tmp";
        std::ofstream file(tmpPath, std::ios::binary | std::ios::trunc);
        if (!file.is_open())
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Cannot write temp file: " + tmpPath);

        file.write(reinterpret_cast<const char*>(header.data()), header.size());
        file.write(reinterpret_cast<const char*>(encRes.value.data()),
                   static_cast<std::streamsize>(encRes.value.size()));
        file.close();

        // Rename to final
        std::error_code ec;
        std::filesystem::rename(tmpPath, filePath, ec);
        if (ec)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Rename failed: " + ec.message());

#ifndef _WIN32
        namespace fs = std::filesystem;
        fs::permissions(filePath,
            fs::perms::owner_read | fs::perms::owner_write,
            fs::perm_options::replace);
#endif
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
        // Read header
        SecBytes header(8);
        file.read(reinterpret_cast<char*>(header.data()), 8);
        if (file.gcount() != 8)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID, "File too short");

        uint32_t magic = 0;
        for (int i = 0; i < 4; ++i) magic |= (header[i] << (i*8));
        if (magic != MAGIC)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID, "Invalid file format");

        uint16_t ver = 0;
        for (int i = 0; i < 2; ++i) ver |= (header[4+i] << (i*8));
        if (ver != VERSION)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID, "Unsupported version");

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

private:
    static std::vector<std::string> splitLine(const std::string& s, char delim) {
        std::vector<std::string> parts;
        std::istringstream iss(s);
        std::string token;
        while (std::getline(iss, token, delim)) parts.push_back(token);
        return parts;
    }

    std::unordered_map<std::string, CredentialRecord> records_;
    mutable bool dirty_ { false };
};

} // namespace SecFW
