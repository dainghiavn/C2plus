#pragma once

#include <string>
#include <vector>
#include <chrono>

class Utils {
public:
    // --- File I/O cơ bản ---
    static std::vector<uint8_t> ReadAllBytes(const std::string& path);
    static bool ReadAllBytes(const std::string& path, std::vector<uint8_t>& out);
    static bool WriteAllBytes(const std::string& path, const std::vector<uint8_t>& data);
    static std::string ChangeExtension(const std::string& inp, const std::string& newExt);

    // --- Password prompt ---
    static std::string PromptPassword(const std::string& prompt, bool mask = true);

    // --- Choice prompt ---
    static int PromptChoice(const std::string& prompt, const std::vector<std::string>& options);

    // --- Cleanup ---
    static void CleanupTemp(const std::string& path);

    // --- Key discovery ---
    static std::string FindFirstPem();

    // --- Permission check ---
    static bool IsAdministrator();

    // --- Formatting ---
    static std::string formatSize(double mb) {
        char buf[64]; snprintf(buf, sizeof(buf), "%.2f MB", mb); return buf;
    }
    static std::string formatTime(double sec) {
        char buf[64]; snprintf(buf, sizeof(buf), "%.2f seconds", sec); return buf;
    }
    static std::string formatSpeed(double mbps) {
        char buf[64]; snprintf(buf, sizeof(buf), "%.2f MB/s", mbps); return buf;
    }

    // --- Log thời gian + tốc độ ---
    static void LogSpeed(const std::string& label, size_t bytes,
        const std::chrono::high_resolution_clock::time_point& start,
        const std::chrono::high_resolution_clock::time_point& end);
};
