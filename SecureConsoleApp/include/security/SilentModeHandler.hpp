#pragma once
// ============================================================
// SilentModeHandler.hpp — v1.3
// Machine-readable (JSON) output mode for third-party consumers.
//
// Design contract — "Framework sets the rules":
//   - Third party calls ./app with fixed CLI flags (nmap-style)
//   - Framework verifies token → checks role → executes read-only action
//   - Output: JSON to stdout ONLY (stderr is suppressed in silent mode)
//   - Every call is audit-logged regardless of outcome
//   - Third party cannot influence format, scope, or action list
//
// Actions (read-only, hard-coded allowlist):
//   ping              — liveness check, no sensitive data
//   list-users        — username + role name per user (no hashes)
//   get-user          — single user info (param: user=<username>)
//   get-audit-log     — recent N audit entries (param: limit=N, filter=ACTION)
//   get-config-key    — single config value by key (param: key=<name>)
//   get-session-list  — currently active sessions (param: none)
//
// Output format:
//   Success: { "status":"ok",    "action":"...", "timestamp":"...",
//              "request_id":"<jti>", "data": <payload> }
//   Error:   { "status":"error", "code":"...",   "message":"...",
//              "timestamp":"..." }
//
// Exit codes:
//   0 = success
//   1 = authentication / authorization error
//   2 = invalid action or parameter
//   3 = internal error
//
// Standards:
//   NIST SP 800-63B §6  (bearer token use)
//   OWASP ASVS V4.1     (access control)
//   NIST SP 800-92      (audit all access)
//   PCI-DSS Req 10      (log every data access)
// ============================================================

#include "SecureCore.hpp"
#include "SilentToken.hpp"
#include "InputValidator.hpp"
#include "SignedAuditLog.hpp"
#include "UserDatabase.hpp"
#include "ConfigManager.hpp"
#include "AuthManager.hpp"
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <span>

namespace SecFW {

// ── Exit codes ────────────────────────────────────────────────────────────────
enum class SilentExitCode : int {
    OK          = 0,
    AUTH_ERROR  = 1,
    BAD_ACTION  = 2,
    INTERNAL    = 3,
};

// ── SilentContext — injected dependencies ─────────────────────────────────────

struct SilentContext {
    SilentTokenManager& tokenMgr;
    UserDatabase&       userDB;
    ConfigManager&      configMgr;
    SignedAuditLog&     auditLog;
    std::string         auditLogPath {};    // path to audit log file for get-audit-log
    // Active sessions — snapshot filled by caller before invoking handle()
    std::vector<SessionToken> activeSessions {};
};

// ── SilentModeHandler ─────────────────────────────────────────────────────────

class SilentModeHandler final {
public:
    SilentModeHandler()  = delete;
    ~SilentModeHandler() = delete;

    // ── handle ────────────────────────────────────────────────────────────────
    //
    // Main entry point called from main() when --silent is detected.
    //
    // tokenStr:  raw token string from --token
    // actionStr: action name from --action
    // params:    key=value pairs from --param flags
    //
    // Returns SilentExitCode — caller should pass this to exit().
    // Output (JSON) is written to stdout.
    // Audit log entry is always written regardless of outcome.

    [[nodiscard]] static SilentExitCode handle(
        SilentContext&                         ctx,
        const std::string&                     tokenStr,
        const std::string&                     actionStr,
        const std::unordered_map<std::string, std::string>& params)
    {
        const std::string ts = nowISO8601();

        // ── 1. Validate action string (before touching token) ─────────────
        // Reject unknown actions with a generic error — don't hint at valid list
        SilentAction action;
        auto actionRes = parseAction(actionStr);
        if (!actionRes.has_value()) {
            // Audit: unknown action attempt
            (void)ctx.auditLog.log("anonymous", "SILENT_UNKNOWN_ACTION",
                false, "action=" + sanitizeParam(actionStr));
            writeError("INVALID_ACTION",
                "Unknown or disallowed action", ts);
            return SilentExitCode::BAD_ACTION;
        }
        action = *actionRes;

        // ── 2. Verify token ───────────────────────────────────────────────
        auto verifyRes = ctx.tokenMgr.verify(tokenStr);
        if (verifyRes.fail()) {
            (void)ctx.auditLog.log("anonymous", "SILENT_AUTH_FAILED",
                false, "reason=" + sanitizeParam(verifyRes.message));
            writeError("AUTH_FAILED", "Authentication failed", ts);
            return SilentExitCode::AUTH_ERROR;
        }

        const auto& payload = verifyRes.value;

        // ── 3. Role-based authorization per action ────────────────────────
        auto authRes = authorize(payload, action);
        if (authRes.fail()) {
            (void)ctx.auditLog.log(payload.sub, "SILENT_AUTHZ_DENIED",
                false, "action=" + actionStr + " role=" + std::to_string(payload.rol));
            writeError("AUTHZ_DENIED", "Insufficient role for this action", ts);
            return SilentExitCode::AUTH_ERROR;
        }

        // ── 4. Validate params ────────────────────────────────────────────
        auto paramRes = validateParams(action, params);
        if (paramRes.fail()) {
            (void)ctx.auditLog.log(payload.sub, "SILENT_BAD_PARAM",
                false, "action=" + actionStr + " " + sanitizeParam(paramRes.message));
            writeError("BAD_PARAM", paramRes.message, ts);
            return SilentExitCode::BAD_ACTION;
        }

        // ── 5. Dispatch ───────────────────────────────────────────────────
        auto result = dispatch(ctx, action, payload, params, ts);

        // ── 6. Audit every successful call — mandatory (PCI-DSS Req 10) ──
        (void)ctx.auditLog.log(
            payload.sub,
            "SILENT_ACCESS",
            result == SilentExitCode::OK,
            "action=" + actionStr + " jti=" + payload.jti);

        return result;
    }

    // ── issueToken ────────────────────────────────────────────────────────────
    //
    // Called from --issue-token flow (interactive, after normal login).
    // Writes token JSON to stdout.

    [[nodiscard]] static SilentExitCode issueToken(
        SilentTokenManager& tokenMgr,
        SignedAuditLog&     auditLog,
        const std::string&  username,
        u32_t               roleFlags,
        int                 ttlSeconds = SILENT_TOKEN_TTL_DEFAULT)
    {
        const std::string ts = nowISO8601();

        auto issueRes = tokenMgr.issue(username, roleFlags, ttlSeconds);
        if (issueRes.fail()) {
            writeError("TOKEN_ISSUE_FAILED", issueRes.message, ts);
            (void)auditLog.log(username, "SILENT_TOKEN_ISSUE_FAIL",
                false, issueRes.message);
            return SilentExitCode::INTERNAL;
        }

        // Parse back to get JTI and expiry for the response
        auto verifyRes = tokenMgr.verify(issueRes.value);
        std::string jti    = verifyRes.ok() ? verifyRes.value.jti : "unknown";
        std::string expiry = verifyRes.ok()
            ? SilentTokenManager::formatTimestamp(verifyRes.value.exp) : "unknown";

        // Output token as JSON
        std::ostringstream json;
        json << "{\n"
             << "  \"status\": \"ok\",\n"
             << "  \"action\": \"issue-token\",\n"
             << "  \"timestamp\": \"" << ts << "\",\n"
             << "  \"data\": {\n"
             << "    \"token\": \""   << issueRes.value << "\",\n"
             << "    \"jti\": \""     << jti << "\",\n"
             << "    \"subject\": \"" << jsonEscape(username) << "\",\n"
             << "    \"expires\": \"" << expiry << "\",\n"
             << "    \"scope\": \"ro\"\n"
             << "  }\n"
             << "}\n";
        std::cout << json.str();

        (void)auditLog.log(username, "SILENT_TOKEN_ISSUED",
            true, "jti=" + jti + " exp=" + expiry);

        return SilentExitCode::OK;
    }

    // ── revokeToken ───────────────────────────────────────────────────────────

    [[nodiscard]] static SilentExitCode revokeToken(
        SilentTokenManager& tokenMgr,
        SignedAuditLog&     auditLog,
        const std::string&  tokenStr,
        const std::string&  revokedBy)
    {
        const std::string ts = nowISO8601();
        auto res = tokenMgr.revoke(tokenStr);
        if (res.fail()) {
            writeError("REVOKE_FAILED", res.message, ts);
            (void)auditLog.log(revokedBy, "SILENT_TOKEN_REVOKE_FAIL",
                false, res.message);
            return SilentExitCode::AUTH_ERROR;
        }
        std::cout << "{\"status\":\"ok\",\"action\":\"revoke-token\","
                  << "\"timestamp\":\"" << ts << "\"}\n";
        (void)auditLog.log(revokedBy, "SILENT_TOKEN_REVOKED", true, "");
        return SilentExitCode::OK;
    }

private:
    // ── Action enum ───────────────────────────────────────────────────────────

    enum class SilentAction {
        PING,             // healthcheck — any authenticated user
        LIST_USERS,       // all users + roles — OPERATOR+
        GET_USER,         // one user — OPERATOR+ (param: user=<name>)
        GET_AUDIT_LOG,    // recent entries — ADMIN+ (param: limit=N, filter=ACTION)
        GET_CONFIG_KEY,   // one config value — ADMIN+ (param: key=<name>)
        GET_SESSION_LIST, // active sessions — ADMIN+
    };

    // ── parseAction ───────────────────────────────────────────────────────────
    [[nodiscard]] static std::optional<SilentAction> parseAction(const std::string& s) {
        // Exact string match — no fuzzy matching (prevent enumeration via typos)
        static const std::unordered_map<std::string, SilentAction> TABLE {
            { "ping",             SilentAction::PING             },
            { "list-users",       SilentAction::LIST_USERS       },
            { "get-user",         SilentAction::GET_USER         },
            { "get-audit-log",    SilentAction::GET_AUDIT_LOG    },
            { "get-config-key",   SilentAction::GET_CONFIG_KEY   },
            { "get-session-list", SilentAction::GET_SESSION_LIST },
        };
        auto it = TABLE.find(s);
        if (it == TABLE.end()) return std::nullopt;
        return it->second;
    }

    // ── authorize — required role per action ──────────────────────────────────
    [[nodiscard]] static Result<void> authorize(
        const SilentTokenPayload& pl, SilentAction action)
    {
        u32_t required = 0;
        switch (action) {
            case SilentAction::PING:             required = Roles::USER;     break;
            case SilentAction::LIST_USERS:       required = Roles::OPERATOR; break;
            case SilentAction::GET_USER:         required = Roles::OPERATOR; break;
            case SilentAction::GET_AUDIT_LOG:    required = Roles::ADMIN;    break;
            case SilentAction::GET_CONFIG_KEY:   required = Roles::ADMIN;    break;
            case SilentAction::GET_SESSION_LIST: required = Roles::ADMIN;    break;
        }
        if (!(pl.rol & required))
            return Result<void>::Failure(SecurityStatus::ERR_AUTH_FAILED,
                "Insufficient role");
        return Result<void>::Success();
    }

    // ── validateParams ────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void> validateParams(
        SilentAction action,
        const std::unordered_map<std::string, std::string>& params)
    {
        // Validate param keys: alphanum + hyphen only
        for (const auto& [k, v] : params) {
            auto kv = InputValidator::validate(k,
                { .minLen=1, .maxLen=32,
                  .regexPattern=R"(^[a-z0-9\-_]+$)" }, "param-key");
            if (kv.fail()) return kv;
            auto vv = InputValidator::validate(v,
                { .minLen=0, .maxLen=256, .checkSQLi=true }, "param-value");
            if (vv.fail()) return vv;
        }

        // Action-specific required params
        if (action == SilentAction::GET_USER) {
            if (!params.count("user") || params.at("user").empty())
                return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "get-user requires --param user=<username>");
            auto uv = InputValidator::validate(params.at("user"),
                Rules::USERNAME, "user");
            if (uv.fail()) return uv;
        }

        if (action == SilentAction::GET_CONFIG_KEY) {
            if (!params.count("key") || params.at("key").empty())
                return Result<void>::Failure(SecurityStatus::ERR_INPUT_INVALID,
                    "get-config-key requires --param key=<name>");
            auto kv = InputValidator::validate(params.at("key"),
                { .minLen=1, .maxLen=128,
                  .regexPattern=R"(^[A-Za-z0-9_.\-]+$)" }, "key");
            if (kv.fail()) return kv;
        }

        if (action == SilentAction::GET_AUDIT_LOG) {
            if (params.count("limit")) {
                auto lr = InputValidator::parseInteger<int>(
                    params.at("limit"), 1, 500);
                if (lr.fail()) return Result<void>::Failure(lr.status,
                    "limit must be 1-500: " + lr.message);
            }
        }

        return Result<void>::Success();
    }

    // ── dispatch ──────────────────────────────────────────────────────────────
    [[nodiscard]] static SilentExitCode dispatch(
        SilentContext&         ctx,
        SilentAction           action,
        const SilentTokenPayload& pl,
        const std::unordered_map<std::string, std::string>& params,
        const std::string&     ts)
    {
        switch (action) {
            case SilentAction::PING:
                return actionPing(pl, ts);
            case SilentAction::LIST_USERS:
                return actionListUsers(ctx.userDB, pl, ts);
            case SilentAction::GET_USER:
                return actionGetUser(ctx.userDB, pl, params, ts);
            case SilentAction::GET_AUDIT_LOG:
                return actionGetAuditLogFromFile(ctx.auditLogPath, pl, params, ts);
            case SilentAction::GET_CONFIG_KEY:
                return actionGetConfigKey(ctx.configMgr, pl, params, ts);
            case SilentAction::GET_SESSION_LIST:
                return actionGetSessionList(ctx.activeSessions, pl, ts);
        }
        writeError("INTERNAL", "Unhandled action", ts);
        return SilentExitCode::INTERNAL;
    }

    // ── Action implementations ────────────────────────────────────────────────

    static SilentExitCode actionPing(
        const SilentTokenPayload& pl, const std::string& ts)
    {
        std::cout << "{\n"
                  << "  \"status\": \"ok\",\n"
                  << "  \"action\": \"ping\",\n"
                  << "  \"timestamp\": \"" << ts << "\",\n"
                  << "  \"request_id\": \"" << pl.jti << "\",\n"
                  << "  \"data\": { \"alive\": true }\n"
                  << "}\n";
        return SilentExitCode::OK;
    }

    static SilentExitCode actionListUsers(
        const UserDatabase& db,
        const SilentTokenPayload& pl,
        const std::string& ts)
    {
        std::ostringstream json;
        json << "{\n"
             << "  \"status\": \"ok\",\n"
             << "  \"action\": \"list-users\",\n"
             << "  \"timestamp\": \"" << ts << "\",\n"
             << "  \"request_id\": \"" << pl.jti << "\",\n"
             << "  \"data\": [\n";

        bool first = true;
        db.forEachUser([&](const std::string& uid, u32_t roles) {
            if (!first) json << ",\n";
            first = false;
            json << "    { \"username\": \"" << jsonEscape(uid)
                 << "\", \"roles\": \""
                 << jsonEscape(Roles::format(roles)) << "\" }";
        });

        json << "\n  ]\n}\n";
        std::cout << json.str();
        return SilentExitCode::OK;
    }

    static SilentExitCode actionGetUser(
        const UserDatabase& db,
        const SilentTokenPayload& pl,
        const std::unordered_map<std::string, std::string>& params,
        const std::string& ts)
    {
        const std::string& username = params.at("user");
        if (!db.hasUser(username)) {
            writeError("NOT_FOUND", "User not found", ts);
            return SilentExitCode::BAD_ACTION;
        }

        // forEachUser to find the specific user's role
        u32_t roles = 0;
        bool found = false;
        db.forEachUser([&](const std::string& uid, u32_t r) {
            if (uid == username) { roles = r; found = true; }
        });

        if (!found) {
            writeError("NOT_FOUND", "User not found", ts);
            return SilentExitCode::BAD_ACTION;
        }

        std::cout << "{\n"
                  << "  \"status\": \"ok\",\n"
                  << "  \"action\": \"get-user\",\n"
                  << "  \"timestamp\": \"" << ts << "\",\n"
                  << "  \"request_id\": \"" << pl.jti << "\",\n"
                  << "  \"data\": {\n"
                  << "    \"username\": \"" << jsonEscape(username) << "\",\n"
                  << "    \"roles\": \""    << jsonEscape(Roles::format(roles)) << "\"\n"
                  << "  }\n"
                  << "}\n";
        return SilentExitCode::OK;
    }

    // ── actionGetAuditLogFromFile — reads log file and returns JSON ─────────
public:
    [[nodiscard]] static SilentExitCode actionGetAuditLogFromFile(
        const std::string&        logPath,
        const SilentTokenPayload& pl,
        const std::unordered_map<std::string, std::string>& params,
        const std::string&        ts)
    {
        int limit = 50;
        if (params.count("limit")) {
            auto lr = InputValidator::parseInteger<int>(params.at("limit"), 1, 500);
            if (lr.ok()) limit = lr.value;
        }
        std::string filterAction;
        if (params.count("filter"))
            filterAction = params.at("filter");

        // Read and parse log file
        std::ifstream f(logPath);
        if (!f.is_open()) {
            writeError("INTERNAL", "Cannot open audit log", ts);
            return SilentExitCode::INTERNAL;
        }

        struct LogRow {
            std::string seq, timestamp, userId, action, result, details;
        };
        std::vector<LogRow> rows;
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty()) continue;
            auto p = splitPipe(line);
            if (p.size() < 6) continue;
            LogRow r { p[0], p[1], p[2], p[3], p[4], p[5] };
            if (!filterAction.empty() && r.action != filterAction) continue;
            rows.push_back(std::move(r));
        }

        // Return last `limit` rows
        std::size_t start = rows.size() > static_cast<std::size_t>(limit)
                          ? rows.size() - limit : 0;

        std::ostringstream json;
        json << "{\n"
             << "  \"status\": \"ok\",\n"
             << "  \"action\": \"get-audit-log\",\n"
             << "  \"timestamp\": \"" << ts << "\",\n"
             << "  \"request_id\": \"" << pl.jti << "\",\n"
             << "  \"data\": [\n";
        for (std::size_t i = start; i < rows.size(); ++i) {
            if (i > start) json << ",\n";
            const auto& r = rows[i];
            json << "    { \"seq\": \""       << jsonEscape(r.seq)       << "\","
                 << " \"timestamp\": \""      << jsonEscape(r.timestamp) << "\","
                 << " \"user\": \""           << jsonEscape(r.userId)    << "\","
                 << " \"action\": \""         << jsonEscape(r.action)    << "\","
                 << " \"result\": \""         << jsonEscape(r.result)    << "\","
                 << " \"details\": \""        << jsonEscape(r.details)   << "\" }";
        }
        json << "\n  ]\n}\n";
        std::cout << json.str();
        return SilentExitCode::OK;
    }

private:
    static SilentExitCode actionGetConfigKey(
        ConfigManager& cfg,
        const SilentTokenPayload& pl,
        const std::unordered_map<std::string, std::string>& params,
        const std::string& ts)
    {
        const std::string& key = params.at("key");
        auto val = cfg.get(key);
        if (!val.has_value()) {
            writeError("NOT_FOUND", "Config key not found", ts);
            return SilentExitCode::BAD_ACTION;
        }

        std::cout << "{\n"
                  << "  \"status\": \"ok\",\n"
                  << "  \"action\": \"get-config-key\",\n"
                  << "  \"timestamp\": \"" << ts << "\",\n"
                  << "  \"request_id\": \"" << pl.jti << "\",\n"
                  << "  \"data\": {\n"
                  << "    \"key\": \""   << jsonEscape(key)            << "\",\n"
                  << "    \"value\": \"" << jsonEscape(std::string(*val)) << "\"\n"
                  << "  }\n"
                  << "}\n";
        return SilentExitCode::OK;
    }

    static SilentExitCode actionGetSessionList(
        const std::vector<SessionToken>& sessions,
        const SilentTokenPayload& pl,
        const std::string& ts)
    {
        std::ostringstream json;
        json << "{\n"
             << "  \"status\": \"ok\",\n"
             << "  \"action\": \"get-session-list\",\n"
             << "  \"timestamp\": \"" << ts << "\",\n"
             << "  \"request_id\": \"" << pl.jti << "\",\n"
             << "  \"data\": [\n";

        bool first = true;
        for (const auto& s : sessions) {
            if (s.isExpired()) continue;
            if (!first) json << ",\n";
            first = false;
            auto remaining = s.remainingTTL().count();
            json << "    { \"token_id\": \""  << jsonEscape(s.tokenId) << "\","
                 << " \"user\": \""           << jsonEscape(s.userId) << "\","
                 << " \"roles\": \""          << jsonEscape(Roles::format(s.roleFlags)) << "\","
                 << " \"remaining_sec\": "    << remaining << " }";
        }

        json << "\n  ]\n}\n";
        std::cout << json.str();
        return SilentExitCode::OK;
    }

    // ── JSON output helpers ───────────────────────────────────────────────────

    static void writeError(
        std::string_view code,
        std::string_view message,
        const std::string& ts)
    {
        std::cout << "{\n"
                  << "  \"status\": \"error\",\n"
                  << "  \"code\": \""    << jsonEscape(std::string(code))    << "\",\n"
                  << "  \"message\": \"" << jsonEscape(std::string(message)) << "\",\n"
                  << "  \"timestamp\": \"" << ts << "\"\n"
                  << "}\n";
    }

    [[nodiscard]] static std::string nowISO8601() {
        auto now = std::chrono::system_clock::now();
        time_t t  = std::chrono::system_clock::to_time_t(now);
        struct tm tm_buf {};
#ifdef _WIN32
        gmtime_s(&tm_buf, &t);
#else
        gmtime_r(&t, &tm_buf);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
        return buf;
    }

    [[nodiscard]] static std::string jsonEscape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s) {
            if      (c == '"')       out += "\\\"";
            else if (c == '\\')      out += "\\\\";
            else if (c == '\n')      out += "\\n";
            else if (c == '\r')      out += "\\r";
            else if (c == '\t')      out += "\\t";
            else if (c < 0x20u) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else out += static_cast<char>(c);
        }
        return out;
    }

    [[nodiscard]] static std::string sanitizeParam(const std::string& s) {
        return InputValidator::sanitize(s).substr(0, 128);
    }

    [[nodiscard]] static std::vector<std::string> splitPipe(const std::string& s) {
        std::vector<std::string> parts;
        std::istringstream iss(s);
        std::string tok;
        while (std::getline(iss, tok, '|')) parts.push_back(tok);
        return parts;
    }
};

} // namespace SecFW
