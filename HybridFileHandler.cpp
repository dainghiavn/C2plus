#include "HybridFileHandler.h"
#include "Logger.h"
#include "Utils.h"

#include <filesystem>
#include <fstream>
#include <vector>
#include <cstring>
#include <ctime>
#include <chrono>

using namespace std;
namespace fs = std::filesystem;

bool HybridFileHandler::Encrypt(const string& outPath,
    const vector<uint8_t>& plain,
    CryptoManager& crypto,
    RSAManager& rsa)
{
    auto& log = Logger::instance();
    log.log(Logger::INFO, "Hybrid Encrypt (RAM) start: " + outPath);

    auto start = chrono::high_resolution_clock::now();

    auto hash = crypto.hashSHA256(plain);
    auto key = CryptoManager::genIv(32);
    auto iv = CryptoManager::genIv(16);
    crypto.setKeyIv(key, iv);

    auto cipher = crypto.encrypt(plain, CryptoManager::MODE_GCM);

    rsa.loadPublicKey("public.pem");
    vector<uint8_t> keyIv;
    keyIv.insert(keyIv.end(), key.begin(), key.end());
    keyIv.insert(keyIv.end(), iv.begin(), iv.end());
    auto ek = rsa.encrypt(keyIv);

    auto end = chrono::high_resolution_clock::now();
    Utils::LogSpeed("Hybrid Encrypt", plain.size(), start, end);

    Header hdr;
    memcpy(hdr.magic, "HYBR", 4);
    hdr.version = 1;
    hdr.aesMode = static_cast<uint8_t>(CryptoManager::MODE_GCM);
    hdr.ekLen = static_cast<uint32_t>(ek.size());
    hdr.timestamp = static_cast<uint64_t>(time(nullptr));

    ofstream ofs(outPath, ios::binary);
    if (!ofs) {
        log.log(Logger::LEVEL_ERROR, "Cannot open " + outPath);
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    ofs.write(reinterpret_cast<const char*>(hash.data()), hash.size());
    ofs.write(reinterpret_cast<const char*>(ek.data()), ek.size());
    ofs.write(reinterpret_cast<const char*>(cipher.data()), cipher.size());
    ofs.flush();
    if (!ofs.good()) {
        log.log(Logger::LEVEL_ERROR, "I/O error writing " + outPath);
        return false;
    }

    log.log(Logger::INFO, "Hybrid Encrypt (RAM) completed: " + outPath);
    return true;
}

bool HybridFileHandler::Decrypt(const string& inPath,
    vector<uint8_t>& plain,
    CryptoManager& crypto,
    RSAManager& rsa)
{
    auto& log = Logger::instance();
    log.log(Logger::INFO, "Hybrid Decrypt (RAM) start: " + inPath);

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
    if (memcmp(hdr->magic, "HYBR", 4) != 0) {
        log.log(Logger::LEVEL_ERROR, "Bad magic");
        return false;
    }

    if (pos + 32 > blob.size()) return false;
    vector<uint8_t> origHash(blob.begin() + pos, blob.begin() + pos + 32);
    pos += 32;

    if (pos + hdr->ekLen > blob.size()) return false;
    vector<uint8_t> ek(blob.begin() + pos, blob.begin() + pos + hdr->ekLen);
    pos += hdr->ekLen;

    vector<uint8_t> cipher(blob.begin() + pos, blob.end());

    auto pem = Utils::FindFirstPem();
    auto pass = Utils::PromptPassword(u8"Nhập passphrase cho private key", true);
    rsa.loadPrivateKey(pem, pass);
    OPENSSL_cleanse(&pass[0], pass.size());

    auto keyIv = rsa.decrypt(ek);
    if (keyIv.size() < 48) {
        log.log(Logger::LEVEL_ERROR, "Bad keyIv length");
        return false;
    }
    vector<uint8_t> key(keyIv.begin(), keyIv.begin() + 32);
    vector<uint8_t> iv(keyIv.begin() + 32, keyIv.begin() + 48);
    crypto.setKeyIv(key, iv);

    auto start = chrono::high_resolution_clock::now();
    plain = crypto.decrypt(cipher, static_cast<CryptoManager::Mode>(hdr->aesMode));
    auto end = chrono::high_resolution_clock::now();
    Utils::LogSpeed("Hybrid Decrypt", plain.size(), start, end);

    if (crypto.hashSHA256(plain) != origHash) {
        log.log(Logger::LEVEL_ERROR, "Integrity check failed");
        return false;
    }

    log.log(Logger::INFO, "Hybrid Decrypt (RAM) done: " + inPath);
    return true;
}

bool HybridFileHandler::EncryptFile(const string& inPath,
    const string& outPath,
    CryptoManager& crypto,
    RSAManager& rsa)
{
    auto size = fs::file_size(inPath);
    if (size <= STREAM_THRESHOLD) {
        auto buf = Utils::ReadAllBytes(inPath);
        return Encrypt(outPath, buf, crypto, rsa);
    }
    return EncryptStream(inPath, outPath, crypto, rsa);
}

bool HybridFileHandler::DecryptFile(const string& inPath,
    const string& outPath,
    CryptoManager& crypto,
    RSAManager& rsa)
{
    auto size = fs::file_size(inPath);
    if (size <= STREAM_THRESHOLD) {
        vector<uint8_t> buf;
        return Decrypt(inPath, buf, crypto, rsa)
            && Utils::WriteAllBytes(outPath, buf);
    }
    return DecryptStream(inPath, outPath, crypto, rsa);
}

bool HybridFileHandler::EncryptStream(const string&, const string&,
    CryptoManager&, RSAManager&)
{
    Logger::instance().log(Logger::LEVEL_ERROR,
        "Hybrid EncryptStream not implemented");
    return false;
}
bool HybridFileHandler::DecryptStream(const string&, const string&,
    CryptoManager&, RSAManager&)
{
    Logger::instance().log(Logger::LEVEL_ERROR,
        "Hybrid DecryptStream not implemented");
    return false;
}
