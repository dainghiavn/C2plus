#pragma once
// ============================================================
// ConsoleCommandRegistry.hpp — NEW FEATURE v1.3
//
// Command-based console application framework.
// Allows building rich, structured console menus with:
//   - Role-based access control per command
//   - Automatic help generation
//   - Command history (in-memory)
//   - Tab-like disambiguation
//   - Audit logging per command
//
// Usage:
//   CommandRegistry reg(ctx, session);
//   reg.add({ "encrypt", "Encrypt data", Roles::USER,
//             [](auto& args) { ... } });
//   reg.runLoop();
//
// ============================================================
#include "SecureCore.hpp"
#include "AuthManager.hpp"
#include "SecureLogger.hpp"
#include "InputValidator.hpp"
#include <functional>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <iostream>

namespace SecFW {

// Command arguments: space-separated tokens after the command name
using CmdArgs = std::vector<std::string>;

// Return value for command handlers
struct CmdResult {
    bool        success { true };
    std::string output  {};
    bool        quit    { false };  // true → exit the command loop

    static CmdResult Ok(std::string msg = "") {
        return { true, std::move(msg), false };
    }
    static CmdResult Err(std::string msg) {
        return { false, std::move(msg), false };
    }
    static CmdResult Quit() {
        return { true, "Goodbye.", true };
    }
};

using CmdHandler = std::function<CmdResult(const CmdArgs&)>;

struct CommandDef {
    std::string name;           // e.g. "encrypt"
    std::string aliases;        // comma-separated, e.g. "enc,e"
    std::string description;
    std::string usage;          // e.g. "encrypt <plaintext>"
    u32_t       requiredRole  { Roles::USER };
    CmdHandler  handler;
    bool        hidden        { false };  // if true, not shown in help
};

// ============================================================
// CommandRegistry
// ============================================================
class CommandRegistry final {
public:
    explicit CommandRegistry(SecureLogger& logger, const SessionToken& session,
                             std::string_view prompt = "> ")
        : logger_(logger), session_(session), prompt_(prompt) {}

    CommandRegistry& add(CommandDef def) {
        // Register primary name
        auto name = def.name;
        handlers_[name] = def;
        order_.push_back(name);

        // Register aliases
        if (!def.aliases.empty()) {
            std::istringstream iss(def.aliases);
            std::string alias;
            while (std::getline(iss, alias, ',')) {
                alias.erase(0, alias.find_first_not_of(" \t"));
                alias.erase(alias.find_last_not_of(" \t") + 1);
                if (!alias.empty()) {
                    aliasMap_[alias] = name;
                }
            }
        }
        return *this;
    }

    // Add built-in commands (help, history, whoami, clear)
    CommandRegistry& addBuiltins() {
        add({ .name        = "help",
              .aliases     = "?",
              .description = "Show available commands",
              .usage       = "help [command]",
              .requiredRole = Roles::GUEST,
              .handler     = [this](const CmdArgs& args) -> CmdResult {
                  if (!args.empty()) return showCommandHelp(args[0]);
                  return showHelp();
              }
        });

        add({ .name        = "whoami",
              .description = "Show current session info",
              .requiredRole = Roles::GUEST,
              .handler     = [this](const CmdArgs&) -> CmdResult {
                  std::ostringstream oss;
                  oss << "User:   " << session_.userId << "\n"
                      << "Roles:  " << formatRoles(session_.roleFlags) << "\n"
                      << "TTL:    " << session_.remainingTTL().count() << "s remaining";
                  return CmdResult::Ok(oss.str());
              }
        });

        add({ .name        = "history",
              .description = "Show command history",
              .requiredRole = Roles::USER,
              .handler     = [this](const CmdArgs&) -> CmdResult {
                  std::ostringstream oss;
                  for (std::size_t i = 0; i < history_.size(); ++i)
                      oss << std::setw(3) << (i + 1) << "  " << history_[i] << "\n";
                  return CmdResult::Ok(oss.str());
              }
        });

        add({ .name        = "exit",
              .aliases     = "quit,logout,q",
              .description = "Exit the console",
              .requiredRole = Roles::GUEST,
              .handler     = [](const CmdArgs&) -> CmdResult {
                  return CmdResult::Quit();
              }
        });

        return *this;
    }

    // ── Main REPL loop ──
    void runLoop() {
        printBanner();

        while (true) {
            // Session expiry check
            if (session_.isExpired()) {
                std::cout << "\n[!] Session expired.\n";
                logger_.audit({.userId=session_.userId, .action="SESSION_EXPIRED",
                               .success=false});
                return;
            }

            std::cout << "[" << session_.userId << "]" << prompt_;
            std::cout.flush();

            std::string line;
            if (!std::getline(std::cin, line) || std::cin.eof()) break;

            // Strip leading/trailing whitespace
            line.erase(0, line.find_first_not_of(" \t"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            if (line.empty()) continue;

            // Null-byte guard
            if (line.find('\0') != std::string::npos) {
                std::cout << "[-] Invalid input\n";
                continue;
            }

            // Length guard
            if (line.size() > 1024) {
                std::cout << "[-] Input too long (max 1024)\n";
                continue;
            }

            // Parse tokens
            auto tokens = tokenize(line);
            if (tokens.empty()) continue;

            std::string cmdName = tokens[0];
            // Lowercase command name
            std::transform(cmdName.begin(), cmdName.end(), cmdName.begin(), ::tolower);
            CmdArgs cmdArgs(tokens.begin() + 1, tokens.end());

            // Resolve alias
            if (aliasMap_.count(cmdName))
                cmdName = aliasMap_.at(cmdName);

            // Add to history (before execution, redact sensitive tokens)
            history_.push_back(cmdName + (cmdArgs.empty() ? "" : " [...]"));
            if (history_.size() > MAX_HISTORY) history_.erase(history_.begin());

            // Find command
            auto it = handlers_.find(cmdName);
            if (it == handlers_.end()) {
                std::cout << "[-] Unknown command: '" << cmdName
                          << "'. Type 'help' for available commands.\n";
                // Suggest similar commands
                auto suggestions = suggest(cmdName);
                if (!suggestions.empty())
                    std::cout << "    Did you mean: " << suggestions << "?\n";
                continue;
            }

            const auto& def = it->second;

            // Role check
            if (!(session_.roleFlags & def.requiredRole)) {
                std::cout << "[-] Access denied: insufficient role for '" << cmdName << "'\n";
                logger_.audit({.userId=session_.userId, .action="CMD_DENIED",
                               .resource=cmdName, .success=false,
                               .details="Insufficient role"});
                continue;
            }

            // Execute
            CmdResult res;
            try {
                res = def.handler(cmdArgs);
            } catch (const std::exception& e) {
                res = CmdResult::Err(std::string("Command exception: ") + e.what());
            }

            // Output result
            if (!res.output.empty())
                std::cout << res.output << "\n";

            // Audit
            logger_.audit({.userId=session_.userId, .action="CMD_" + cmdName,
                           .success=res.success,
                           .details=res.success ? "" : res.output});

            if (res.quit) return;
        }
    }

private:
    CmdResult showHelp() const {
        std::ostringstream oss;
        oss << "\nAvailable commands:\n";

        std::size_t colW = 10;
        for (const auto& name : order_) {
            const auto& def = handlers_.at(name);
            if (def.hidden) continue;
            if (!(session_.roleFlags & def.requiredRole)) continue;
            colW = std::max(colW, name.size());
        }

        for (const auto& name : order_) {
            const auto& def = handlers_.at(name);
            if (def.hidden) continue;
            if (!(session_.roleFlags & def.requiredRole)) continue;
            oss << "  " << std::left << std::setw(static_cast<int>(colW + 2)) << name
                << def.description;
            if (!def.aliases.empty()) oss << " (aliases: " << def.aliases << ")";
            oss << "\n";
        }
        return CmdResult::Ok(oss.str());
    }

    CmdResult showCommandHelp(const std::string& name) const {
        auto it = handlers_.find(name);
        if (it == handlers_.end())
            return CmdResult::Err("No help for: " + name);
        const auto& def = it->second;
        std::ostringstream oss;
        oss << "Command: " << def.name << "\n"
            << "Description: " << def.description << "\n";
        if (!def.usage.empty())   oss << "Usage: " << def.usage << "\n";
        if (!def.aliases.empty()) oss << "Aliases: " << def.aliases << "\n";
        return CmdResult::Ok(oss.str());
    }

    void printBanner() const {
        std::cout << "Type 'help' for available commands, 'exit' to quit.\n";
    }

    // Suggest commands by Levenshtein distance ≤ 2
    std::string suggest(const std::string& input) const {
        std::vector<std::string> candidates;
        for (const auto& name : order_) {
            if (levenshtein(input, name) <= 2)
                candidates.push_back(name);
        }
        std::string result;
        for (std::size_t i = 0; i < candidates.size(); ++i) {
            if (i > 0) result += ", ";
            result += candidates[i];
        }
        return result;
    }

    static std::vector<std::string> tokenize(const std::string& line) {
        std::vector<std::string> tokens;
        std::istringstream iss(line);
        std::string token;
        bool inQuote = false;
        std::string current;

        for (char c : line) {
            if (c == '"') {
                inQuote = !inQuote;
            } else if (c == ' ' && !inQuote) {
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
            } else {
                current += c;
            }
        }
        if (!current.empty()) tokens.push_back(current);
        return tokens;
    }

    static std::string formatRoles(u32_t flags) {
        std::string s;
        if (flags & Roles::SUPER)    return "SUPER";
        if (flags & Roles::ADMIN)    s += "ADMIN ";
        if (flags & Roles::OPERATOR) s += "OPERATOR ";
        if (flags & Roles::USER)     s += "USER ";
        if (flags & Roles::GUEST)    s += "GUEST";
        if (s.empty()) s = "NONE";
        return s;
    }

    // Simple Levenshtein distance for typo detection
    static int levenshtein(const std::string& a, const std::string& b) {
        int m = static_cast<int>(a.size());
        int n = static_cast<int>(b.size());
        std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));
        for (int i = 0; i <= m; ++i) dp[i][0] = i;
        for (int j = 0; j <= n; ++j) dp[0][j] = j;
        for (int i = 1; i <= m; ++i)
            for (int j = 1; j <= n; ++j)
                dp[i][j] = (a[i-1] == b[j-1])
                    ? dp[i-1][j-1]
                    : 1 + std::min({dp[i-1][j], dp[i][j-1], dp[i-1][j-1]});
        return dp[m][n];
    }

    static constexpr std::size_t MAX_HISTORY = 100;

    SecureLogger&             logger_;
    const SessionToken&       session_;
    std::string               prompt_;
    std::unordered_map<std::string, CommandDef> handlers_;
    std::unordered_map<std::string, std::string> aliasMap_;
    std::vector<std::string>  order_;
    std::vector<std::string>  history_;
};

} // namespace SecFW
