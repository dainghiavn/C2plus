#include "AESFileHandler.h"
#include "Logger.h"
#include "Utils.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <cstring>
#include <ctime>
#include <chrono>

using namespace std;
namespace fs = std::filesystem;

bool AESFileHandler::Encrypt(const string& outPath,
    const vector<uint8_t>& plain,
    CryptoManager& crypto)
{
    auto& log = Logger::instance();
    log.log(Logger::INFO, "AES Encrypt (RAM) start: " + outPath);

    auto hash = crypto.hashSHA256(plain);
    auto salt = CryptoManager::genIv(16);
    auto iv = CryptoManager::genIv(16);

    auto pwd = Utils::PromptPassword(u8"Nhập mật khẩu cho AES", true);
    auto pwd2 = Utils::PromptPassword(u8"Xác nhận mật khẩu", true);
    if (pwd != pwd2) {
        log.log(Logger::LEVEL_ERROR, u8"AES Encrypt: mật khẩu không khớp");
        cerr << u8"Error: mật khẩu không khớp\n";
        return false;
    }

    const uint32_t iterations = 100000;
    crypto.deriveKey(pwd, salt, iterations);
    crypto.setKeyIv(crypto.getKey(), iv);
    OPENSSL_cleanse(&pwd[0], pwd.size());
    OPENSSL_cleanse(&pwd2[0], pwd2.size());

    auto start = chrono::high_resolution_clock::now();
    auto cipher = crypto.encrypt(plain, CryptoManager::MODE_GCM);
    auto end = chrono::high_resolution_clock::now();
    Utils::LogSpeed("AES Encrypt", plain.size(), start, end);

    Header hdr;
    memcpy(hdr.magic, "SENC", 4);
    hdr.version = 1;
    hdr.aesMode = static_cast<uint8_t>(CryptoManager::MODE_GCM);
    hdr.iterations = iterations;
    hdr.saltLen = static_cast<uint16_t>(salt.size());
    hdr.ivLen = static_cast<uint16_t>(iv.size());
    hdr.timestamp = static_cast<uint64_t>(time(nullptr));

    ofstream ofs(outPath, ios::binary);
    if (!ofs) {
        log.log(Logger::LEVEL_ERROR, "Cannot open " + outPath);
        return false;
    }

    ofs.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    ofs.write(reinterpret_cast<const char*>(hash.data()), hash.size());
    ofs.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    ofs.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    uint32_t clen = static_cast<uint32_t>(cipher.size());
    ofs.write(reinterpret_cast<const char*>(&clen), sizeof(clen));
    ofs.write(reinterpret_cast<const char*>(cipher.data()), clen);
    ofs.flush();

    if (!ofs.good()) {
        log.log(Logger::LEVEL_ERROR, "I/O error writing " + outPath);
        return false;
    }

    log.log(Logger::INFO, "AES Encrypt (RAM) completed: " + outPath);
    return true;
}

bool AESFileHandler::Decrypt(const string& inPath,
    vector<uint8_t>& plain,
    CryptoManager& crypto)
{
    auto& log = Logger::instance();
    log.log(Logger::INFO, "AES Decrypt (RAM) start: " + inPath);

    vector<uint8_t> blob;
    if (!Utils::ReadAllBytes(inPath, blob)) {
        log.log(Logger::LEVEL_ERROR, "Cannot read " + inPath);
        return false;
    }

    size_t pos = 0;
    if (blob.size() < sizeof(Header)) {
        log.log(Logger::LEVEL_ERROR, "File too small");
        return false;
    }

    auto* hdr = reinterpret_cast<const Header*>(blob.data());
    pos += sizeof(Header);

    if (memcmp(hdr->magic, "SENC", 4) != 0) {
        log.log(Logger::LEVEL_ERROR, "Bad magic");
        return false;
    }

    vector<uint8_t> origHash(blob.begin() + pos, blob.begin() + pos + 32);
    pos += 32;
    vector<uint8_t> salt(blob.begin() + pos, blob.begin() + pos + hdr->saltLen);
    pos += hdr->saltLen;
    vector<uint8_t> iv(blob.begin() + pos, blob.begin() + pos + hdr->ivLen);
    pos += hdr->ivLen;

    uint32_t clen = 0;
    memcpy(&clen, blob.data() + pos, sizeof(clen));
    pos += sizeof(clen);
    if (pos + clen > blob.size()) {
        log.log(Logger::LEVEL_ERROR, "Bad cipher length");
        return false;
    }
    vector<uint8_t> cipher(blob.begin() + pos, blob.begin() + pos + clen);

    auto pwd = Utils::PromptPassword(u8"Nhập mật khẩu cho AES", true);
    try {
        crypto.deriveKey(pwd, salt, hdr->iterations);
        crypto.setKeyIv(crypto.getKey(), iv);
        OPENSSL_cleanse(&pwd[0], pwd.size());
    }
    catch (std::exception& ex) {
        log.log(Logger::LEVEL_ERROR, "Key derivation failed: " + string(ex.what()));
        return false;
    }

    vector<uint8_t> dec;
    try {
        auto start = chrono::high_resolution_clock::now();
        dec = crypto.decrypt(cipher, static_cast<CryptoManager::Mode>(hdr->aesMode));
        auto end = chrono::high_resolution_clock::now();
        Utils::LogSpeed("AES Decrypt", dec.size(), start, end);
    }
    catch (std::exception& ex) {
        log.log(Logger::LEVEL_ERROR, "Decrypt error: " + string(ex.what()));
        return false;
    }

    if (crypto.hashSHA256(dec) != origHash) {
        log.log(Logger::LEVEL_ERROR, "Integrity check failed");
        return false;
    }

    plain = std::move(dec);
    log.log(Logger::INFO, "AES Decrypt (RAM) done: " + inPath);
    return true;
}

bool AESFileHandler::EncryptFile(const string& inPath,
    const string& outPath,
    CryptoManager& crypto)
{
    auto size = fs::file_size(inPath);
    if (size <= STREAM_THRESHOLD) {
        auto buf = Utils::ReadAllBytes(inPath);
        return Encrypt(outPath, buf, crypto);
    }
    return EncryptStream(inPath, outPath, crypto);
}

bool AESFileHandler::DecryptFile(const string& inPath,
    const string& outPath,
    CryptoManager& crypto)
{
    auto size = fs::file_size(inPath);
    if (size <= STREAM_THRESHOLD) {
        vector<uint8_t> buf;
        return Decrypt(inPath, buf, crypto)
            && Utils::WriteAllBytes(outPath, buf);
    }
    return DecryptStream(inPath, outPath, crypto);
}

bool AESFileHandler::EncryptStream(const string& inPath,
    const string& outPath,
    CryptoManager& crypto)
{
    Logger::instance().log(Logger::LEVEL_ERROR,
        "AES EncryptStream not implemented");
    return false;
}

bool AESFileHandler::DecryptStream(const string& inPath,
    const string& outPath,
    CryptoManager& crypto)
{
    Logger::instance().log(Logger::LEVEL_ERROR,
        "AES DecryptStream not implemented");
    return false;
}