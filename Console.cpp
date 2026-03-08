// Console.cpp

#include "EncFileHandler.h"
#include "CryptoManager.h"
#include "RSAManager.h"
#include "KeyGenTool.h"
#include "Utils.h"
#include "Logger.h"

#include <iostream>
#include <filesystem>
#include <vector>
#include <string>
#include <stdexcept>

static void PrintUsage() {
    std::cout <<
        "Usage:\n"
        "  genkey <bits> <private_out.pem> <public_out.pem>\n"
        "  encrypt <input_file> [output_file.enc]\n"
        "  decrypt <input_file.enc> [output_file]\n\n"
        "If output is omitted:\n"
        "  foo.txt -> foo.enc   (encrypt)\n"
        "  foo.enc  -> foo.dec  (decrypt)\n";
}

int main(int argc, char* argv[]) {
    Logger::instance().setLogFile("console.log");
    Logger::instance().enableConsole(false);

    // check quyền admin
    Logger::instance().log(
        Utils::IsAdministrator() ? Logger::INFO : Logger::WARNING,
        "Running as " + std::string(Utils::IsAdministrator() ? "Administrator" : "normal user")
    );

    try {
        CryptoManager   crypto;
        RSAManager      rsa;
        EncFileHandler  enc;

        if (argc < 2) {
            PrintUsage();
            return 1;
        }

        std::string cmd = argv[1];
        if (cmd == "genkey") {
            if (argc != 5) { PrintUsage(); return 1; }
            int bits = std::stoi(argv[2]);
            std::string priv = argv[3], pub = argv[4];
            std::string pass = Utils::PromptPassword(u8"Nhập passphrase cho private key", true);
            KeyGenTool::GenerateRSAKey(bits, priv, pub, pass);
            std::cout << "Key pair generated:\n"
                << "  Private: " << priv << "\n"
                << "  Public : " << pub << "\n";
            return 0;
        }
        else if (cmd == "encrypt") {
            if (argc < 3 || argc > 4) { PrintUsage(); return 1; }
            std::string inPath = argv[2];
            std::string outPath = (argc == 4
                ? argv[3]
                : Utils::ChangeExtension(inPath, ".enc"));
            if (std::filesystem::path(outPath).extension() != ".enc")
                outPath = Utils::ChangeExtension(outPath, ".enc");

            // gọi streaming encrypt
            bool ok = enc.Save(inPath, outPath, crypto, rsa);
            if (ok) {
                std::cout << "Encrypt succeeded -> " << outPath << "\n";
                Logger::instance().log(Logger::INFO, "Encrypt succeeded: " + outPath);
                return 0;
            }
            else {
                std::cerr << "Encrypt failed\n";
                Logger::instance().log(Logger::LEVEL_ERROR, "Encrypt failed: " + inPath);
                return 1;
            }
        }
        else if (cmd == "decrypt") {
            if (argc < 3 || argc > 4) { PrintUsage(); return 1; }
            std::string inPath = argv[2];
            std::string outPath = (argc == 4
                ? argv[3]
                : Utils::ChangeExtension(inPath, ".dec"));
            if (std::filesystem::path(outPath).extension() == ".enc")
                outPath = Utils::ChangeExtension(outPath, ".dec");

            // gọi streaming decrypt trực tiếp ra file
            bool ok = enc.LoadToFile(inPath, outPath, crypto, rsa);
            if (ok) {
                std::cout << "Decrypt succeeded -> " << outPath << "\n";
                Logger::instance().log(Logger::INFO,
                    "Decrypt succeeded: " + inPath + " -> " + outPath);
                return 0;
            }
            else {
                std::cerr << "Decrypt failed\n";
                Logger::instance().log(Logger::LEVEL_ERROR, "Decrypt failed: " + inPath);
                return 1;
            }
        }
        else {
            PrintUsage();
            return 1;
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        Logger::instance().log(Logger::LEVEL_ERROR, std::string("Exception: ") + ex.what());
        return 1;
    }
}
