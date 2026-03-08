#include "RSAManager.h"
#include "Logger.h"

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <vector>
#include <cstdio>

static std::string getOsslError() {
    unsigned long e = ERR_get_error();
    if (!e) return {};
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(" | OpenSSL error: ") + buf;
}

RSAManager::RSAManager() {
    // Với OpenSSL ≥1.1, không cần ERR_load_crypto_strings / OpenSSL_add_all_algorithms
    Logger::instance().log(Logger::INFO, "RSAManager initialized");
}

RSAManager::~RSAManager() {
    if (pubKey_)  EVP_PKEY_free(pubKey_);
    if (privKey_) EVP_PKEY_free(privKey_);
    Logger::instance().log(Logger::INFO, "RSAManager destroyed");
}

void RSAManager::loadPublicKey(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (!bio) throw RSAException("Cannot open public key file: " + path);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) throw RSAException("Invalid public key: " + path + getOsslError());
    if (pubKey_) EVP_PKEY_free(pubKey_);
    pubKey_ = pkey;
    Logger::instance().log(Logger::INFO, "Loaded RSA public key: " + path);
}

void RSAManager::loadPrivateKey(const std::string& path, const std::string& pwd) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (!bio) throw RSAException("Cannot open private key file: " + path);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(
        bio, nullptr, nullptr,
        pwd.empty() ? nullptr : (void*)pwd.c_str());
    BIO_free(bio);
    if (!pkey) throw RSAException("Invalid private key or passphrase: " + path + getOsslError());
    if (privKey_) EVP_PKEY_free(privKey_);
    privKey_ = pkey;
    Logger::instance().log(Logger::INFO, "Loaded RSA private key: " + path);
}

std::vector<uint8_t> RSAManager::encrypt(const std::vector<uint8_t>& data) {
    if (!pubKey_) throw RSAException("Public key not loaded");
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubKey_, nullptr);
    if (!ctx) throw RSAException("EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw RSAException("RSA_encrypt init failed" + getOsslError());
    }
    size_t outLen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw RSAException("RSA_encrypt sizing failed" + getOsslError());
    }
    std::vector<uint8_t> out(outLen);
    if (EVP_PKEY_encrypt(ctx, out.data(), &outLen, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw RSAException("RSA_encrypt failed" + getOsslError());
    }
    out.resize(outLen);
    EVP_PKEY_CTX_free(ctx);
    Logger::instance().log(Logger::INFO, "Data encrypted (RSA OAEP)");
    return out;
}

std::vector<uint8_t> RSAManager::decrypt(const std::vector<uint8_t>& data) {
    if (!privKey_) throw RSAException("Private key not loaded");
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey_, nullptr);
    if (!ctx) throw RSAException("EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw RSAException("RSA_decrypt init failed" + getOsslError());
    }
    size_t outLen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw RSAException("RSA_decrypt sizing failed" + getOsslError());
    }
    std::vector<uint8_t> out(outLen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outLen, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw RSAException("RSA_decrypt failed" + getOsslError());
    }
    out.resize(outLen);
    EVP_PKEY_CTX_free(ctx);
    Logger::instance().log(Logger::INFO, "Data decrypted (RSA OAEP)");
    return out;
}

size_t RSAManager::keySize() const {
    if (privKey_) return EVP_PKEY_get_size(privKey_);
    if (pubKey_)  return EVP_PKEY_get_size(pubKey_);
    return 0;
}
