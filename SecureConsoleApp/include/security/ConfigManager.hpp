#pragma once
// ============================================================
// ConfigManager.hpp
// Standards: OWASP Configuration Guide, NIST SP 800-53 CM-6
// ============================================================
#include "SecureCore.hpp"
#include "CryptoEngine.hpp"
#include <fstream>
#include <unordered_map>
#include <filesystem>
#include <sstream>
#include <optional>

namespace SecFW {

class ConfigManager final {
public:
    static constexpr std::size_t MAX_FILE_SIZE = 16 * 1024 * 1024; // 16 MB

    [[nodiscard]] Result<void> loadEncrypted(
        const std::string& filePath,
        std::span<const byte_t> masterKey)
    {
        namespace fs = std::filesystem;
        if (!fs::exists(filePath))
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Config file not found: " + filePath);

        auto size = fs::file_size(filePath);
        if (size > MAX_FILE_SIZE)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Config file too large (>16MB)");

#ifndef _WIN32
        auto perms = fs::status(filePath).permissions();
        if ((perms & fs::perms::group_read)  != fs::perms::none ||
            (perms & fs::perms::others_read) != fs::perms::none)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Config file permissions too permissive (must be 600)");
#endif

        std::ifstream file(filePath, std::ios::binary);
        SecBytes encrypted((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());

        auto decResult = CryptoEngine::decryptAESGCM(encrypted, masterKey);
        if (decResult.fail())
            return Result<void>::Failure(decResult.status,
                "Config decryption failed: " + decResult.message);

        std::string content(decResult.value.begin(), decResult.value.end());
        parseKV(content);
        return Result<void>::Success();
    }

    [[nodiscard]] Result<void> loadPlaintext(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file.is_open())
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "Cannot open config: " + filePath);
        std::string content((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
        parseKV(content);
        return Result<void>::Success();
    }

    [[nodiscard]] std::optional<std::string> get(const std::string& key) const {
        auto it = store_.find(key);
        if (it == store_.end()) return std::nullopt;
        return it->second;
    }

    [[nodiscard]] std::string getOrDefault(const std::string& key,
                                           std::string_view defaultVal) const {
        auto v = get(key);
        return v.value_or(std::string(defaultVal));
    }

    [[nodiscard]] Result<void> validateNoHardcodedSecrets() const {
        const std::vector<std::string> sensitiveKeys = {
            "password", "secret", "api_key", "token", "private_key"
        };
        for (const auto& [k, v] : store_) {
            std::string kLower(k);
            std::transform(kLower.begin(), kLower.end(), kLower.begin(), ::tolower);
            for (const auto& sk : sensitiveKeys) {
                if (kLower.find(sk) != std::string::npos &&
                    !v.empty() && v != "${ENV}" && v.substr(0, 4) != "enc:")
                    return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                        "Potential hardcoded secret in key: " + k);
            }
        }
        return Result<void>::Success();
    }

private:
    void parseKV(const std::string& content) {
        std::istringstream iss(content);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto pos = line.find('=');
            if (pos == std::string::npos) continue;
            std::string key   = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t\r\n") + 1);
            store_[key] = value;
        }
    }
    std::unordered_map<std::string, std::string> store_;
};

} // namespace SecFW
