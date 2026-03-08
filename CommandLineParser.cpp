#include "CommandLineParser.h"
#include <iostream>

CommandLineParser::CommandLineParser(int argc, char* argv[]) {
    Parse(argc, argv);
}

void CommandLineParser::Parse(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--", 0) == 0 && i + 1 < argc) {
            std::string key = arg.substr(2);
            std::string value = argv[i + 1];
            options[key] = value;
            ++i; // skip next value
        }
    }
}

bool CommandLineParser::HasOption(const std::string& name) const {
    return options.find(name) != options.end();
}

std::string CommandLineParser::GetOption(const std::string& name, const std::string& defaultValue) const {
    auto it = options.find(name);
    return it != options.end() ? it->second : defaultValue;
}

void CommandLineParser::PrintHelp() const {
    std::cout << "Usage:\n"
        << "  console encrypt        --input <file>   --output <file>  --mode aes|hybrid --pass <password> | --key <pubkey.pem>\n"
        << "  console decrypt        --input <file>   --output <file>  --mode aes|hybrid --pass <password> | --key <privkey.pem>\n"
        << "  console encrypt-folder --input <folder> --output <file>  --mode aes|hybrid --format zip|tar  --pass|--key\n"
        << "  console genkey         --type rsa|ecc   --bits <2048/4096> --out-priv <priv.pem> --out-pub <pub.pem> [--pass <passphrase>]\n";
}

