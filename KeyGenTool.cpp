#include "KeyGenTool.h"
#include "Logger.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <memory>
#include <vector>
#include <stdexcept>

struct PKeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) { if (p) EVP_PKEY_CTX_free(p); } };
struct PKeyDeleter { void operator()(EVP_PKEY* p) { if (p) EVP_PKEY_free(p); } };
struct BioDeleter { void operator()(BIO* b) { if (b) BIO_free(b); } };

static std::string getOpenSslError() {
    unsigned long e = ERR_get_error();
    if (!e) return {};
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(" | OpenSSL error: ") + buf;
}

void KeyGenTool::GenerateRSAKey(int bits,
    const std::string& privOut,
    const std::string& pubOut,
    const std::string& passphrase)
{
    try {
        auto ctx = std::unique_ptr<EVP_PKEY_CTX, PKeyCtxDeleter>(
            EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
        if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0)
        {
            throw std::runtime_error("RSA keygen init failed" + getOpenSslError());
        }

        EVP_PKEY* rawKey = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &rawKey) <= 0) {
            throw std::runtime_error("RSA keygen failed" + getOpenSslError());
        }
        std::unique_ptr<EVP_PKEY, PKeyDeleter> pkey(rawKey);

        // Prepare passphrase buffer
        std::vector<unsigned char> passBuf(
            passphrase.begin(), passphrase.end());

        // Write private key (AES-256-CBC encrypted PEM)
        auto bioPriv = std::unique_ptr<BIO, BioDeleter>(
            BIO_new_file(privOut.c_str(), "wb"));
        if (!bioPriv) throw std::runtime_error("Open priv file failed" + getOpenSslError());

        if (!PEM_write_bio_PrivateKey(
            bioPriv.get(), pkey.get(),
            EVP_aes_256_cbc(),
            passBuf.empty() ? nullptr : passBuf.data(),
            static_cast<int>(passBuf.size()),
            nullptr, nullptr))
        {
            throw std::runtime_error("Write private key failed" + getOpenSslError());
        }

        // Clear passphrase from memory
        OPENSSL_cleanse(passBuf.data(), passBuf.size());

        // Write public key
        auto bioPub = std::unique_ptr<BIO, BioDeleter>(
            BIO_new_file(pubOut.c_str(), "wb"));
        if (!bioPub) throw std::runtime_error("Open pub file failed" + getOpenSslError());

        if (!PEM_write_bio_PUBKEY(bioPub.get(), pkey.get())) {
            throw std::runtime_error("Write public key failed" + getOpenSslError());
        }

        Logger::instance().log(Logger::INFO,
            "GenerateRSAKey success (bits=" + std::to_string(bits) +
            ", priv=" + privOut + ", pub=" + pubOut + ")");
    }
    catch (const std::exception& ex) {
        Logger::instance().log(Logger::LEVEL_ERROR,
            std::string("GenerateRSAKey failed: ") + ex.what());
        throw;
    }
}
