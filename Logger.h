#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream> 

class Logger {
public:
    enum Level { INFO, WARNING, LEVEL_ERROR };

    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    void setLogFile(const std::string& path) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (ofs_.is_open()) ofs_.close();
        ofs_.open(path, std::ios::app);
    }

    void enableConsole(bool enabled) {
        std::lock_guard<std::mutex> lk(mtx_);
        consoleEnabled_ = enabled;
    }

    void log(Level lvl, const std::string& msg) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        std::tm tm;
#if defined(_WIN32)
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm, "%F %T")
            << '.' << std::setw(3) << std::setfill('0') << ms.count()
            << " [" << levelName(lvl) << "] " << msg;

        std::string fullMsg = oss.str();

        if (ofs_.is_open()) {
            ofs_ << fullMsg << "\n";
            ofs_.flush();
        }

        if (consoleEnabled_) {
            std::cout << fullMsg << std::endl;
        }
    }

private:
    Logger() = default;
    ~Logger() { if (ofs_.is_open()) ofs_.close(); }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    const char* levelName(Level lvl) {
        switch (lvl) {
        case INFO: return "INFO";
        case WARNING: return "WARN";
        case LEVEL_ERROR: return "ERROR";
        }
        return "UNK";
    }

    std::ofstream ofs_;
    std::mutex mtx_;
    bool consoleEnabled_ = true;  // mặc định bật console
};
