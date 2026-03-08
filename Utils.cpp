#include "Utils.h"
#include "Logger.h"

#include <fstream>
#include <iostream>
#include <cstdio>
#include <filesystem>
#include <algorithm>
#include <stdexcept>
#include <limits>

#ifdef _WIN32
# include <conio.h>
#include <Windows.h>
#else
# include <termios.h>
# include <unistd.h>
#endif


std::vector<uint8_t> Utils::ReadAllBytes(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) throw std::runtime_error("Cannot open file: " + path);
    auto size = ifs.tellg();
    if (size < 0) throw std::runtime_error("Empty or invalid file: " + path);
    ifs.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    if (!ifs.read(reinterpret_cast<char*>(buf.data()), size))
        throw std::runtime_error("Read file failed: " + path);
    return buf;
}

bool Utils::ReadAllBytes(const std::string& path, std::vector<uint8_t>& out) {
    try {
        out = ReadAllBytes(path);
        return true;
    }
    catch (const std::exception& ex) {
        Logger::instance().log(Logger::LEVEL_ERROR, ex.what());
        return false;
    }
}

bool Utils::WriteAllBytes(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        Logger::instance().log(Logger::LEVEL_ERROR, "Cannot write file: " + path);
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    ofs.flush();
    if (!ofs.good()) {
        Logger::instance().log(Logger::LEVEL_ERROR, "Write failed: " + path);
        return false;
    }
    return true;
}

std::string Utils::ChangeExtension(const std::string& inp, const std::string& newExt) {
    std::filesystem::path p(inp);
    if (p.has_extension()) p.replace_extension(newExt);
    else                   p += newExt;
    return p.string();
}

std::string Utils::PromptPassword(const std::string& prompt, bool mask) {
    std::cout << prompt << ": " << std::flush;
    std::string pwd;
#ifdef _WIN32
    while (true) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') { std::cout << "\n"; break; }
        if (ch == '\b') {
            if (!pwd.empty()) {
                pwd.pop_back();
                if (mask) std::cout << "\b \b" << std::flush;
            }
        }
        else {
            pwd.push_back(static_cast<char>(ch));
            if (mask) std::cout << '*' << std::flush;
        }
    }
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, pwd);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
#endif
    return pwd;
}

int Utils::PromptChoice(const std::string& prompt, const std::vector<std::string>& options) {
    std::cout << prompt << "\n";
    for (size_t i = 0; i < options.size(); ++i) {
        std::cout << "  [" << i << "] " << options[i] << "\n";
    }
    std::cout << u8"Chọn số: " << std::flush;
    int choice = -1;
    while (true) {
        if (!(std::cin >> choice) || choice < 0 || choice >= (int)options.size()) {
            std::cin.clear();
            std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
            std::cout << u8"Vui lòng nhập lại (0–" << options.size() - 1 << "): " << std::flush;
        }
        else {
            std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
            break;
        }
    }
    return choice;
}

void Utils::CleanupTemp(const std::string& path) {
    if (std::remove(path.c_str()) == 0)
        Logger::instance().log(Logger::INFO, "Deleted temp: " + path);
    else
        Logger::instance().log(Logger::WARNING, "Temp delete failed: " + path);
}

std::string Utils::FindFirstPem() {
    namespace fs = std::filesystem;
    auto cwd = fs::current_path();
    for (auto& entry : fs::directory_iterator(cwd)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (ext == ".pem") {
            std::string found = entry.path().string();
            Logger::instance().log(Logger::INFO, "Utils::FindFirstPem found: " + found);
            return found;
        }
    }
    throw std::runtime_error("No .pem key file found in current directory");
}

bool Utils::IsAdministrator() {
#ifdef _WIN32
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
#else
    return geteuid() == 0;
#endif
}

void Utils::LogSpeed(const std::string& label, size_t bytes,
    const std::chrono::high_resolution_clock::time_point& start,
    const std::chrono::high_resolution_clock::time_point& end)
{
    double seconds = std::chrono::duration<double>(end - start).count();
    double mb = bytes / (1024.0 * 1024.0);
    char msg[128];
    snprintf(msg, sizeof(msg), "%s: %.2f MB in %.2f seconds (%.2f MB/s)",
        label.c_str(), mb, seconds, mb / seconds);
    Logger::instance().log(Logger::INFO, msg);
}
