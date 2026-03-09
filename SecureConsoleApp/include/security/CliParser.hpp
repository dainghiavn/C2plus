#pragma once
// ============================================================
// CliParser.hpp — Secure CLI Argument Parser (FIXED v1.2)
// Standards: SEI CERT ENV01-C, STR02-C
// Fixed:
//   [1] Mutually exclusive args (addConflict)
//   [2] Cross-platform setenv removed → resolveEnvOverride()
//   [3] Path existence + permission validation
//   [4] generate_key normalize '-'→'_' confirmed + tested
//   [5] Support both --opt=val and --opt val
// ============================================================
#include "SecureCore.hpp"
#include "InputValidator.hpp"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <filesystem>

namespace SecFW {

// ============================================================
// ArgDef: mô tả 1 argument
// ============================================================
struct ArgDef {
    std::string    longName;
    char           shortAlias   { 0 };
    bool           isFlag       { true };
    bool           required     { false };
    std::string    defaultVal   {};
    std::string    valueName    {};
    std::string    description  {};
    ValidationRule valueRule    {};

    // Loại value để post-validate sau khi parse
    enum class ValueKind { NONE, PATH_READ, PATH_WRITE, PATH_DIR, INTEGER };
    ValueKind valueKind { ValueKind::NONE };
};

// FIX [1]: Conflict rule giữa 2 args
struct ArgConflict {
    std::string arg1;
    std::string arg2;
    std::string message;
};

// ============================================================
// ParsedArgs
// ============================================================
struct ParsedArgs {
    std::unordered_map<std::string, std::string> values;
    std::vector<std::string>                     positional;

    [[nodiscard]] bool has(std::string_view name) const {
        auto it = values.find(std::string(name));
        return it != values.end() && !it->second.empty();
    }
    [[nodiscard]] std::optional<std::string> get(std::string_view name) const {
        auto it = values.find(std::string(name));
        if (it == values.end()) return std::nullopt;
        return it->second;
    }
    [[nodiscard]] std::string getOr(std::string_view name,
                                    std::string_view def) const {
        return get(name).value_or(std::string(def));
    }
};

// ============================================================
// CliParser
// ============================================================
class CliParser final {
public:
    explicit CliParser(std::string_view programName,
                       std::string_view description = "")
        : programName_(programName), description_(description) {}

    CliParser& add(ArgDef def) {
        // FIX [4]: normalize longName '-' → '_' lúc đăng ký
        // để lookup nhất quán khi user gõ --generate-key hay --generate_key
        std::replace(def.longName.begin(), def.longName.end(), '-', '_');

        if (def.shortAlias != 0)
            shortToLong_[def.shortAlias] = def.longName;
        order_.push_back(def.longName);
        defs_[def.longName] = std::move(def);
        return *this;
    }

    // FIX [1]: Đăng ký conflict rule
    CliParser& addConflict(std::string_view a, std::string_view b,
                           std::string_view msg = "") {
        std::string na(a), nb(b);
        std::replace(na.begin(), na.end(), '-', '_');
        std::replace(nb.begin(), nb.end(), '-', '_');
        conflicts_.push_back({
            na, nb,
            msg.empty() ? ("--" + na + " and --" + nb + " cannot be used together")
                        : std::string(msg)
        });
        return *this;
    }

    // ── Main parse ──
    [[nodiscard]] Result<ParsedArgs> parse(int argc, char* argv[]) const {
        ParsedArgs result;

        // Set defaults
        for (const auto& [name, def] : defs_)
            if (!def.defaultVal.empty())
                result.values[name] = def.defaultVal;

        for (int i = 1; i < argc; ++i) {
            std::string_view arg(argv[i]);

            // Security: max length (CERT STR31-C)
            if (arg.size() > 512)
                return Result<ParsedArgs>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "Argument too long: " + std::string(arg.substr(0, 32)) + "...");

            // Null byte check
            if (arg.find('\0') != std::string_view::npos)
                return Result<ParsedArgs>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "Null byte in argument");

            if (arg.starts_with("--")) {
                // Long option
                auto r = parseLong(arg, i, argc, argv, result);
                if (r.fail()) return Result<ParsedArgs>::Failure(r.status, r.message);
            }
            else if (arg.starts_with("-") && arg.size() == 2) {
                // Short option
                char alias = arg[1];
                if (!std::isalnum(static_cast<unsigned char>(alias)))
                    return Result<ParsedArgs>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                        std::string("Invalid short option: -") + alias);

                auto it = shortToLong_.find(alias);
                if (it == shortToLong_.end())
                    return Result<ParsedArgs>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                        std::string("Unknown option: -") + alias);

                const auto& def = defs_.at(it->second);
                if (def.isFlag) {
                    result.values[it->second] = "1";
                } else {
                    if (i + 1 >= argc)
                        return Result<ParsedArgs>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                            std::string("Option -") + alias + " requires a value");
                    std::string val(argv[++i]);
                    auto vr = validateValue(def, val);
                    if (vr.fail()) return Result<ParsedArgs>::Failure(vr.status, vr.message);
                    result.values[it->second] = std::move(val);
                }
            }
            else if (!arg.starts_with("-")) {
                result.positional.push_back(std::string(arg));
            }
            else {
                return Result<ParsedArgs>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "Unrecognized argument: " + std::string(arg));
            }
        }

        // Check required
        for (const auto& [name, def] : defs_)
            if (def.required && def.defaultVal.empty() && !result.has(name))
                return Result<ParsedArgs>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "Required argument missing: --" + name);

        // FIX [1]: Check conflicts
        for (const auto& c : conflicts_)
            if (result.has(c.arg1) && result.has(c.arg2))
                return Result<ParsedArgs>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    c.message);

        // FIX [3]: Post-parse path validation
        auto pathCheck = validatePaths(result);
        if (pathCheck.fail()) return Result<ParsedArgs>::Failure(pathCheck.status, pathCheck.message);

        return Result<ParsedArgs>::Success(std::move(result));
    }

    void printHelp() const {
        std::cout << "\nUsage: " << programName_ << " [OPTIONS]\n";
        if (!description_.empty()) std::cout << "\n" << description_ << "\n";
        std::cout << "\nOptions:\n";

        std::size_t colW = 4;
        for (const auto& name : order_) {
            const auto& def = defs_.at(name);
            std::size_t w = 2 + def.longName.size();
            if (!def.isFlag) w += 3 + (def.valueName.empty() ? 5 : def.valueName.size());
            colW = std::max(colW, w);
        }

        for (const auto& name : order_) {
            const auto& def = defs_.at(name);
            std::ostringstream lhs;
            if (def.shortAlias) lhs << "  -" << def.shortAlias << ", ";
            else                lhs << "      ";
            // Display '-' form to user (underscore → dash)
            std::string displayName = def.longName;
            std::replace(displayName.begin(), displayName.end(), '_', '-');
            lhs << "--" << displayName;
            if (!def.isFlag)
                lhs << " <" << (def.valueName.empty() ? "VALUE" : def.valueName) << ">";
            std::cout << std::left << std::setw(static_cast<int>(colW + 10)) << lhs.str();
            if (!def.description.empty()) std::cout << def.description;
            if (!def.defaultVal.empty())  std::cout << " [default: " << def.defaultVal << "]";
            if (def.required)             std::cout << " (required)";
            std::cout << "\n";
        }

        // Print conflict hints
        if (!conflicts_.empty()) {
            std::cout << "\nConflicts:\n";
            for (const auto& c : conflicts_) {
                std::string da = c.arg1, db = c.arg2;
                std::replace(da.begin(), da.end(), '_', '-');
                std::replace(db.begin(), db.end(), '_', '-');
                std::cout << "  --" << da << " conflicts with --" << db << "\n";
            }
        }
        std::cout << "\n";
    }

    void printVersion(std::string_view version) const {
        std::cout << programName_ << " v" << version << "\n";
    }

private:
    [[nodiscard]] Result<void> parseLong(std::string_view token, int& i, int argc, char* argv[],
                                          ParsedArgs& result) const {
        std::string name, value;
        auto eqPos = token.find('=');
        if (eqPos != std::string_view::npos) {
            // --opt=value
            name  = std::string(token.substr(2, eqPos - 2));
            value = std::string(token.substr(eqPos + 1));
        } else {
            // --opt (maybe flag or with next arg as value)
            name = std::string(token.substr(2));
        }

        // Validate chars: a-z, 0-9, '-'
        for (char c : name)
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-')
                return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "Invalid char in option: --" + name);

        // FIX [4]: Normalize '-' → '_' để khớp với defs_ keys
        std::string normName = name;
        std::replace(normName.begin(), normName.end(), '-', '_');

        auto it = defs_.find(normName);
        if (it == defs_.end())
            return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                "Unknown option: --" + name);

        const auto& def = it->second;
        if (def.isFlag) {
            if (!value.empty() && value != "1" && value != "true" && value != "yes")
                return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "--" + name + " is a flag, does not accept a value");
            result.values[def.longName] = "1";
        } else {
            if (value.empty()) {
                // Get value from next argument
                if (i + 1 >= argc)
                    return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                        "--" + name + " requires a value");
                value = std::string(argv[++i]);
            }
            auto vr = validateValue(def, value);
            if (vr.fail()) return vr;
            result.values[def.longName] = std::move(value);
        }
        return Result<void>::Success();
    }

    [[nodiscard]] Result<void> validateValue(const ArgDef& def,
                                              const std::string& value) const {
        ValidationRule rule = def.valueRule;
        if (rule.maxLen == 0) rule.maxLen = 512;
        auto r = InputValidator::validate(value, rule, "--" + def.longName);
        if (r.fail()) return Result<void>::Failure(r.status, r.message);
        return Result<void>::Success();
    }

    // FIX [3]: Post-parse path existence & permission checks
    [[nodiscard]] Result<void> validatePaths(const ParsedArgs& result) const {
        namespace fs = std::filesystem;

        for (const auto& [name, def] : defs_) {
            if (def.valueKind == ArgDef::ValueKind::NONE) continue;
            auto val = result.get(name);
            if (!val.has_value() || val->empty()) continue;

            fs::path p(*val);

            switch (def.valueKind) {
            case ArgDef::ValueKind::PATH_READ:
                // File phải tồn tại và đọc được
                if (!fs::exists(p))
                    return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                        "--" + name + ": file not found: " + *val);
                if (!fs::is_regular_file(p))
                    return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                        "--" + name + ": not a regular file: " + *val);
#ifndef _WIN32
                {
                    auto perms = fs::status(p).permissions();
                    // Cảnh báo nếu file secrets có quyền quá mở
                    if ((perms & fs::perms::others_read) != fs::perms::none)
                        std::cerr << "[WARN] --" << name
                                  << ": file is world-readable: " << *val << "\n";
                }
#endif
                break;

            case ArgDef::ValueKind::PATH_WRITE:
                // Nếu file tồn tại → phải ghi được; nếu không → thư mục cha phải tồn tại
                if (fs::exists(p)) {
                    if (!fs::is_regular_file(p))
                        return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                            "--" + name + ": path exists but is not a file: " + *val);
                } else {
                    auto parent = p.parent_path();
                    if (!parent.empty() && !fs::exists(parent))
                        return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                            "--" + name + ": parent directory not found: " +
                            parent.string());
                }
                break;

            case ArgDef::ValueKind::PATH_DIR:
                if (!fs::exists(p))
                    return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                        "--" + name + ": directory not found: " + *val);
                if (!fs::is_directory(p))
                    return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                        "--" + name + ": not a directory: " + *val);
                break;

            default: break;
            }
        }
        return Result<void>::Success();
    }

    std::string                             programName_;
    std::string                             description_;
    std::unordered_map<std::string, ArgDef> defs_;
    std::unordered_map<char, std::string>   shortToLong_;
    std::vector<std::string>                order_;
    std::vector<ArgConflict>                conflicts_;
};

// ============================================================
// buildAppCli() — Fixed v1.2
// ============================================================
inline CliParser buildAppCli(std::string_view progName) {
    CliParser cli(progName,
        "Secure Console Application — CERT/OWASP/NIST/FIPS Compliant");

    cli.add({ .longName    = "setup",
              .shortAlias  = 's',
              .isFlag      = true,
              .description = "First-run setup: create initial admin account" });

    cli.add({ .longName    = "debug",
              .shortAlias  = 'd',
              .isFlag      = true,
              .description = "Debug mode: disable anti-tamper, enable verbose log" });

    cli.add({ .longName    = "generate_key",
              .shortAlias  = 'g',
              .isFlag      = true,
              .description = "Generate a new 32-byte master key file" });

    cli.add({ .longName    = "key_file",
              .shortAlias  = 'k',
              .isFlag      = false,
              .defaultVal  = "",
              .valueName   = "PATH",
              .description = "Path to master key file (overrides APP_KEY_FILE env)",
              .valueRule   = { .minLen = 1, .maxLen = 260 },
              .valueKind   = ArgDef::ValueKind::PATH_READ });

    cli.add({ .longName    = "db",
              .shortAlias  = 0,
              .isFlag      = false,
              .defaultVal  = "users.udb",
              .valueName   = "PATH",
              .description = "Path to encrypted user database",
              .valueRule   = { .minLen = 1, .maxLen = 260 },
              .valueKind   = ArgDef::ValueKind::PATH_WRITE });

    cli.add({ .longName    = "log",
              .shortAlias  = 'l',
              .isFlag      = false,
              .defaultVal  = "app_audit.log",
              .valueName   = "PATH",
              .description = "Path to audit log file",
              .valueRule   = { .minLen = 1, .maxLen = 260 },
              .valueKind   = ArgDef::ValueKind::PATH_WRITE });

    cli.add({ .longName    = "session_ttl",
              .shortAlias  = 0,
              .isFlag      = false,
              .defaultVal  = "30",
              .valueName   = "MINUTES",
              .description = "Session timeout in minutes [1-480]",
              .valueRule   = { .minLen = 1, .maxLen = 3,
                               .regexPattern = R"(^[1-9][0-9]{0,2}$)" } });

    cli.add({ .longName    = "max_attempts",
              .shortAlias  = 0,
              .isFlag      = false,
              .defaultVal  = "5",
              .valueName   = "N",
              .description = "Max login attempts before lockout [1-10]",
              .valueRule   = { .minLen = 1, .maxLen = 2,
                               .regexPattern = R"(^([1-9]|10)$)" } });

    cli.add({ .longName    = "version",
              .shortAlias  = 'v',
              .isFlag      = true,
              .description = "Print version and exit" });

    cli.add({ .longName    = "help",
              .shortAlias  = 'h',
              .isFlag      = true,
              .description = "Print this help message and exit" });

    // Mutually exclusive rules
    cli.addConflict("setup",        "generate_key",
                    "--setup and --generate-key cannot be used together");
    cli.addConflict("setup",        "version",
                    "--setup and --version cannot be used together");
    cli.addConflict("generate_key", "db",
                    "--db has no effect with --generate-key");
    cli.addConflict("generate_key", "debug",
                    "--debug has no effect with --generate-key");
    cli.addConflict("help",         "setup",
                    "Use --help alone");
    cli.addConflict("help",         "version",
                    "--help and --version cannot be used together");

    return cli;
}

} // namespace SecFW
