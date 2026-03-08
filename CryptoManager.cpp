#include "CryptoManager.h"
#include "Logger.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <memory>
#include <cstring>

struct EVPCTXDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
    }
};
struct MDCTXDeleter {
    void operator()(EVP_MD_CTX* ctx) const {
        if (ctx) EVP_MD_CTX_free(ctx);
    }
};

CryptoManager::CryptoManager() {
    // OpenSSL ≥1.1 auto init; nếu <1.1, gọi thêm ở main()
    Logger::instance().log(Logger::INFO, "CryptoManager initialized");
}

CryptoManager::~CryptoManager() {
    if (!key_.empty())
        OPENSSL_cleanse(key_.data(), static_cast<int>(key_.size()));
    if (!iv_.empty())
        OPENSSL_cleanse(iv_.data(), static_cast<int>(iv_.size()));
    Logger::instance().log(Logger::INFO, "CryptoManager destroyed");
}

void CryptoManager::deriveKey(const std::string& password,
    const std::vector<uint8_t>& salt,
    int iterations)
{
    key_.assign(32, 0);
    // PBKDF2 → key
    if (!PKCS5_PBKDF2_HMAC(
        password.data(),
        static_cast<int>(password.size()),
        salt.data(),
        static_cast<int>(salt.size()),
        iterations,
        EVP_sha256(),
        static_cast<int>(key_.size()),
        key_.data()
    )) {
        throw CryptoException("PBKDF2 error");
    }
    Logger::instance().log(Logger::INFO, "deriveKey completed");
}

std::vector<uint8_t> CryptoManager::genIv(size_t len) {
    std::vector<uint8_t> iv(len);
    if (RAND_bytes(iv.data(), static_cast<int>(len)) != 1)
        throw CryptoException("IV generation failed");
    Logger::instance().log(Logger::INFO, "IV generated");
    return iv;
}

void CryptoManager::setKeyIv(const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv)
{
    if (key.size() != 32 || iv.size() != 16)
        throw CryptoException("Invalid key/iv size");
    key_ = key;
    iv_ = iv;
    Logger::instance().log(Logger::INFO, "setKeyIv called");
}

std::vector<uint8_t> CryptoManager::encrypt(const std::vector<uint8_t>& plain,
    Mode mode)
{
    const EVP_CIPHER* cipherType =
        (mode == MODE_GCM ? EVP_aes_256_gcm() : EVP_aes_256_cbc());
    auto ctx = std::unique_ptr<EVP_CIPHER_CTX, EVPCTXDeleter>(EVP_CIPHER_CTX_new());
    if (!ctx) throw CryptoException("Cipher context init failed");
    if (EVP_EncryptInit_ex(ctx.get(), cipherType, nullptr, key_.data(), iv_.data()) != 1)
        throw CryptoException("EncryptInit error");

    std::vector<uint8_t> out(plain.size() + EVP_CIPHER_block_size(cipherType));
    int outLen = 0, tmpLen = 0;

    if (EVP_EncryptUpdate(ctx.get(), out.data(), &outLen,
        plain.data(), static_cast<int>(plain.size())) != 1)
        throw CryptoException("EncryptUpdate error");

    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + outLen, &tmpLen) != 1)
        throw CryptoException("EncryptFinal error");
    outLen += tmpLen;
    out.resize(outLen);

    if (mode == MODE_GCM) {
        // append tag
        uint8_t tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
            throw CryptoException("GCM get tag error");
        out.insert(out.end(), tag, tag + sizeof(tag));
    }

    Logger::instance().log(
        Logger::INFO,
        std::string("Data encrypted (") + (mode == MODE_GCM ? "GCM" : "CBC") + ")"
    );
    return out;
}

std::vector<uint8_t> CryptoManager::decrypt(const std::vector<uint8_t>& cipher,
    Mode mode)
{
    const EVP_CIPHER* cipherType =
        (mode == MODE_GCM ? EVP_aes_256_gcm() : EVP_aes_256_cbc());
    auto ctx = std::unique_ptr<EVP_CIPHER_CTX, EVPCTXDeleter>(EVP_CIPHER_CTX_new());
    if (!ctx) throw CryptoException("Cipher context init failed");

    std::vector<uint8_t> data = cipher;
    // if GCM, strip tag
    std::vector<uint8_t> tag;
    if (mode == MODE_GCM) {
        if (data.size() < 16) throw CryptoException("Cipher too short for GCM tag");
        tag.assign(data.end() - 16, data.end());
        data.resize(data.size() - 16);
    }

    if (EVP_DecryptInit_ex(ctx.get(), cipherType, nullptr, key_.data(), iv_.data()) != 1)
        throw CryptoException("DecryptInit error");

    if (mode == MODE_GCM) {
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, (int)tag.size(), tag.data()) != 1)
            throw CryptoException("GCM set tag error");
    }

    std::vector<uint8_t> out(data.size());
    int outLen = 0, tmpLen = 0;

    if (EVP_DecryptUpdate(ctx.get(), out.data(), &outLen,
        data.data(), static_cast<int>(data.size())) != 1)
        throw CryptoException("DecryptUpdate error");

    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + outLen, &tmpLen) != 1)
        throw CryptoException("DecryptFinal (tag verify) error");
    outLen += tmpLen;
    out.resize(outLen);

    Logger::instance().log(
        Logger::INFO,
        std::string("Data decrypted (") + (mode == MODE_GCM ? "GCM" : "CBC") + ")"
    );
    return out;
}

std::vector<uint8_t> CryptoManager::hashSHA256(const std::vector<uint8_t>& data) {
    unsigned int len = 0;
    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    auto ctx = std::unique_ptr<EVP_MD_CTX, MDCTXDeleter>(EVP_MD_CTX_new());
    if (!ctx) throw CryptoException("MD_CTX init failed");
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), digest.data(), &len) != 1)
        throw CryptoException("SHA256 error");
    digest.resize(len);
    return digest;
}
