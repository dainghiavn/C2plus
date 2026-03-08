#pragma once

#include <string>
#include <stdexcept>

/// Công cụ sinh cặp khóa RSA (private + public) PEM.
/// Private key được mã hóa AES-256-CBC với passphrase.
class KeyGenTool {
public:
    /// Sinh cặp RSA key
    /// @param bits       độ dài key (2048, 3072, 4096)
    /// @param privOut    file private.pem (được mã hóa)
    /// @param pubOut     file public.pem
    /// @param passphrase mật khẩu mã hóa private key
    /// @throws std::runtime_error if error
    static void GenerateRSAKey(int bits,
        const std::string& privOut,
        const std::string& pubOut,
        const std::string& passphrase);
};
