#pragma once
// ============================================================
// PrivilegeDrop.hpp — NEW FEATURE v1.3
//
// Principle of Least Privilege: Drop root/elevated privileges
// after startup (before handling user input).
//
// Usage:
//   if (auto r = PrivilegeDrop::drop("appuser", "appgroup"); r.fail())
//       { /* handle error */ }
//
// Also provides:
//   - SecureChroot: change root to a sandboxed directory
//   - SecureFileLimits: set resource limits (RLIMIT_NOFILE, etc.)
//
// Standards: SEI CERT POS02-C, CWE-250, OWASP Configuration
// ============================================================
#include "SecureCore.hpp"
#include <string>
#include <iostream>

#ifndef _WIN32
  #include <pwd.h>
  #include <grp.h>
  #include <unistd.h>
  #include <sys/resource.h>
  #include <sys/stat.h>
#endif

namespace SecFW {

class PrivilegeDrop final {
public:
#ifndef _WIN32
    // ── Drop to specified user/group ──
    [[nodiscard]] static Result<void> drop(
        const std::string& username,
        const std::string& groupname = "")
    {
        if (::getuid() != 0 && ::geteuid() != 0) {
            // Already non-root — nothing to do (not an error)
            return Result<void>::Success();
        }

        // Resolve group
        if (!groupname.empty()) {
            struct group* gr = ::getgrnam(groupname.c_str());
            if (!gr)
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "Group not found: " + groupname);
            if (::setgid(gr->gr_gid) != 0)
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "setgid failed for group: " + groupname);
        }

        // Resolve user
        struct passwd* pw = ::getpwnam(username.c_str());
        if (!pw)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "User not found: " + username);

        // Set supplementary groups
        if (::initgroups(username.c_str(), pw->pw_gid) != 0)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "initgroups failed for: " + username);

        // Set GID (if group not explicitly specified)
        if (groupname.empty()) {
            if (::setgid(pw->pw_gid) != 0)
                return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                    "setgid failed");
        }

        // Drop UID
        if (::setuid(pw->pw_uid) != 0)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "setuid failed for user: " + username);

        // Verify we can't re-escalate (CERT POS02-C)
        if (::setuid(0) == 0)
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "CRITICAL: Re-escalation to root succeeded — privilege drop failed!");

        return Result<void>::Success();
    }

    // ── Get current effective user info ──
    [[nodiscard]] static std::string currentUser() {
        struct passwd* pw = ::getpwuid(::geteuid());
        if (!pw) return std::to_string(::geteuid());
        return std::string(pw->pw_name);
    }

    [[nodiscard]] static bool isRoot() noexcept {
        return ::getuid() == 0 || ::geteuid() == 0;
    }

    // ── Chroot to a sandboxed directory ──
    [[nodiscard]] static Result<void> chroot(const std::string& dir) {
        if (::chdir(dir.c_str()) != 0)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "chdir to sandbox failed: " + dir);
        if (::chroot(dir.c_str()) != 0)
            return Result<void>::Failure(SecurityStatus::ERR_CONFIG_INVALID,
                "chroot failed: " + dir);
        // chdir to "/" inside the chroot (important!)
        if (::chdir("/") != 0)
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "chdir to / inside chroot failed");
        return Result<void>::Success();
    }

    // ── Set resource limits ──
    struct ResourceLimits {
        rlim_t maxOpenFiles   { 256 };
        rlim_t maxCoreDump    { 0 };       // 0 = disable core dumps (security)
        rlim_t maxStackSize   { 8 * 1024 * 1024 }; // 8 MB
        rlim_t maxProcesses   { 64 };
        rlim_t maxFileSize    { 100 * 1024 * 1024 }; // 100 MB max file write
    };

    [[nodiscard]] static Result<void> setLimits(const ResourceLimits& limits = {}) {
        auto setLimit = [](int resource, rlim_t soft, rlim_t hard) -> bool {
            struct rlimit rl { soft, hard };
            return ::setrlimit(resource, &rl) == 0;
        };

        if (!setLimit(RLIMIT_NOFILE, limits.maxOpenFiles, limits.maxOpenFiles))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "setrlimit(NOFILE) failed");

        if (!setLimit(RLIMIT_CORE, limits.maxCoreDump, limits.maxCoreDump))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "setrlimit(CORE) failed");

        if (!setLimit(RLIMIT_STACK, limits.maxStackSize, limits.maxStackSize))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "setrlimit(STACK) failed");

        if (!setLimit(RLIMIT_NPROC, limits.maxProcesses, limits.maxProcesses))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "setrlimit(NPROC) failed");

        if (!setLimit(RLIMIT_FSIZE, limits.maxFileSize, limits.maxFileSize))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "setrlimit(FSIZE) failed");

        return Result<void>::Success();
    }

    // ── Set umask for file creation ──
    static void setSecureUmask() {
        // 0077 = owner-only rw (files: 600, dirs: 700)
        ::umask(0077);
    }

    // ── Combined hardening: limits + umask (call before processing user data) ──
    [[nodiscard]] static Result<void> harden() {
        setSecureUmask();
        auto r = setLimits();
        if (r.fail()) return r;
        return Result<void>::Success();
    }

#else
// ============================================================
// Windows Implementation
// ============================================================
// NOTE: True privilege dropping on Windows requires token manipulation
// (CreateRestrictedToken / AdjustTokenPrivileges) — complex and
// application-specific. The stubs below compile cleanly; a production
// Windows deployment should implement full token restriction.
// ============================================================
#include <aclapi.h>
#pragma comment(lib, "advapi32.lib")

    [[nodiscard]] static Result<void> drop(
        const std::string&, const std::string& = "") {
        // TODO: Implement CreateRestrictedToken / AdjustTokenPrivileges
        // for full least-privilege on Windows.
        return Result<void>::Success();
    }

    [[nodiscard]] static bool isRoot() noexcept {
        // Check if running as Administrator
        BOOL isAdmin = FALSE;
        PSID adminGroup = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuthority, 2,
                SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(nullptr, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        return isAdmin == TRUE;
    }

    // ── Apply owner-only ACL to a sensitive file ──
    // Equivalent of chmod 600 on Windows using explicit DACL
    [[nodiscard]] static Result<void> setFileOwnerOnly(const std::string& filePath) {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "OpenProcessToken failed: " + std::to_string(GetLastError()));

        // Get current user SID
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
        std::vector<BYTE> buffer(dwSize);
        if (!GetTokenInformation(hToken, TokenUser, buffer.data(), dwSize, &dwSize)) {
            CloseHandle(hToken);
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "GetTokenInformation failed");
        }
        CloseHandle(hToken);

        TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
        PSID ownerSid = tokenUser->User.Sid;

        // Build DACL: owner = GENERIC_READ | GENERIC_WRITE, everyone else = deny
        EXPLICIT_ACCESS ea{};
        ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
        ea.grfAccessMode        = SET_ACCESS;
        ea.grfInheritance       = NO_INHERITANCE;
        ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName    = reinterpret_cast<LPTSTR>(ownerSid);

        PACL pDACL = nullptr;
        if (SetEntriesInAcl(1, &ea, nullptr, &pDACL) != ERROR_SUCCESS)
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "SetEntriesInAcl failed");

        DWORD result = SetNamedSecurityInfoA(
            const_cast<char*>(filePath.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, pDACL, nullptr);
        LocalFree(pDACL);

        if (result != ERROR_SUCCESS)
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "SetNamedSecurityInfo failed: " + std::to_string(result));

        return Result<void>::Success();
    }

    // ── Windows harden: apply Job Object limits ──
    [[nodiscard]] static Result<void> harden() {
        // Create a Job Object to limit this process
        HANDLE hJob = CreateJobObject(nullptr, nullptr);
        if (!hJob)
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "CreateJobObject failed");

        JOBOBJECT_BASIC_LIMIT_INFORMATION limits{};
        limits.LimitFlags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimits{};
        extLimits.BasicLimitInformation = limits;

        if (!SetInformationJobObject(hJob,
                JobObjectExtendedLimitInformation,
                &extLimits, sizeof(extLimits))) {
            CloseHandle(hJob);
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "SetInformationJobObject failed");
        }

        if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
            CloseHandle(hJob);
            return Result<void>::Failure(SecurityStatus::ERR_INTERNAL,
                "AssignProcessToJobObject failed");
        }

        // hJob intentionally not closed — job object lifetime = process lifetime
        return Result<void>::Success();
    }

    [[nodiscard]] static std::string currentUser() {
        char buf[256] = {};
        DWORD len = sizeof(buf);
        if (GetUserNameA(buf, &len)) return std::string(buf);
        return "unknown";
    }
#endif
};

} // namespace SecFW
