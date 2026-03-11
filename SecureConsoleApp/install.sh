#!/usr/bin/env bash
# =============================================================================
#  SecureConsoleApp — One-Line Installer
#
#  Cách dùng (1 lệnh duy nhất):
#  bash -c "$(curl -fsSL https://raw.githubusercontent.com/dainghiavn/C2plus/main/SecureConsoleApp/install.sh)"
#
#  Repo  : github.com/dainghiavn/C2plus
#  App   : SecureConsoleApp v1.3
#  Std   : FIPS 140-3 · NIST SP 800-x · SEI CERT C++ · OWASP ASVS
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ── CONFIG ────────────────────────────────────────────────────────────────────
readonly REPO_CLONE="https://github.com/dainghiavn/C2plus.git"
readonly APP_SUBDIR="SecureConsoleApp"
readonly APP_VERSION="1.3"
readonly INSTALL_DIR="${HOME}/SecureConsoleApp"
readonly LOG_FILE="/tmp/secure_install_$(date +%Y%m%d_%H%M%S).log"
readonly OPENSSL_MIN=3
readonly GCC_MIN=12
readonly CMAKE_MIN_MAJ=3
readonly CMAKE_MIN_MIN=20

# ── COLORS ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  R='\033[0;31m'  G='\033[0;32m'  Y='\033[1;33m'  B='\033[0;34m'
  C='\033[0;36m'  M='\033[0;35m'  W='\033[1;37m'  DIM='\033[2m'
  BOLD='\033[1m'  NC='\033[0m'
  HIDE='\033[?25l'  SHOW='\033[?25h'  CLR='\r\033[K'
else
  R='' G='' Y='' B='' C='' M='' W='' DIM='' BOLD='' NC=''
  HIDE='' SHOW='' CLR=''
fi

# ── SPINNER ───────────────────────────────────────────────────────────────────
SP=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
SP_PID=""

spin_start() {
    printf "${HIDE}"
    local msg="${1:-}"
    ( local i=0
      while true; do
          printf "${CLR}   ${C}${SP[$((i%10))]}${NC}  ${DIM}${msg}${NC}"
          ((i++)) || true; sleep 0.08
      done ) &
    SP_PID=$!
}
spin_stop() {
    [[ -n "${SP_PID}" ]] && {
        kill "${SP_PID}" 2>/dev/null
        wait "${SP_PID}" 2>/dev/null || true
        SP_PID=""
    }
    printf "${CLR}${SHOW}"
}

# ── HELPERS ───────────────────────────────────────────────────────────────────
_log() { echo "$(date '+%H:%M:%S') $*" >> "${LOG_FILE}"; }
ok()   { spin_stop; printf "  ${G}✔${NC}  ${W}${1}${NC}\n";   _log "[OK]  $1"; }
info() {             printf "  ${C}›${NC}  ${DIM}${1}${NC}\n"; _log "[INF] $1"; }
warn() {             printf "  ${Y}⚠${NC}  ${Y}${1}${NC}\n";  _log "[WRN] $1"; }

die() {
    spin_stop
    printf "\n  ${R}${BOLD}✖  THẤT BẠI:${NC} ${R}${1}${NC}\n"
    printf "  ${DIM}Log: ${LOG_FILE}${NC}\n\n"
    exit 1
}

step() {
    local n="$1" t="$2" label="$3"
    printf "\n  ${BOLD}${B}[${n}/${t}]${NC} ${BOLD}${W}${label}${NC}\n"
    printf "  ${DIM}$(printf '─%.0s' {1..52})${NC}\n"
    _log "STEP ${n}/${t}: ${label}"
}

run() {
    local desc="$1"; shift
    _log "$ $*"
    if ! "$@" >> "${LOG_FILE}" 2>&1; then
        die "${desc} — xem log: ${LOG_FILE}"
    fi
}

# FIX: wrapper sudo — nếu đang là root thì chạy thẳng, không cần sudo
_sudo() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# ── BANNER ────────────────────────────────────────────────────────────────────
banner() {
    clear
    printf "${C}${BOLD}"
    cat << 'ART'

   ╔═══════════════════════════════════════════════════════════╗
   ║                                                           ║
   ║    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗    ║
   ║    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ║
   ║    ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗      ║
   ║    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝      ║
   ║    ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗    ║
   ║    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ║
   ║                                                           ║
   ╚═══════════════════════════════════════════════════════════╝
ART
    printf "${NC}\n"
    printf "   ${BOLD}${W}C++ Security Framework${NC}  ${DIM}v${APP_VERSION}${NC}\n"
    printf "   ${DIM}AES-256-GCM · PBKDF2 · TOTP 2FA · HKDF · Anti-Tamper${NC}\n\n"
    printf "   ${DIM}[${NC}${BOLD}${G}FIPS 140-3${NC}${DIM}] [${NC}${BOLD}${C}NIST SP 800-x${NC}${DIM}] [${NC}${BOLD}${Y}OWASP ASVS${NC}${DIM}] [${NC}${BOLD}${M}SEI CERT C++${NC}${DIM}] [${NC}${BOLD}${B}PCI-DSS Req10${NC}${DIM}]${NC}\n"
    printf "\n   ${DIM}Repo  : ${C}github.com/dainghiavn/C2plus${NC}\n"
    printf "   ${DIM}Log   : ${LOG_FILE}${NC}\n"
    printf "\n   ${DIM}$(printf '═%.0s' {1..61})${NC}\n\n"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOTAL=8

# FIX: Lấy username thực tế — hoạt động đúng cả khi chạy root, sudo, hay user thường
get_real_user() {
    # Ưu tiên: SUDO_USER → logname → USER → whoami
    if [[ -n "${SUDO_USER:-}" ]]; then
        echo "${SUDO_USER}"
    elif logname 2>/dev/null; then
        : # logname đã in ra
    else
        echo "${USER:-$(whoami)}"
    fi
}

s1_preflight() {
    step 1 ${TOTAL} "Kiểm tra hệ thống (Preflight)"

    # OS
    spin_start "Phát hiện OS..."
    [[ -f /etc/os-release ]] || die "/etc/os-release không tồn tại."
    # shellcheck source=/dev/null
    source /etc/os-release
    spin_stop
    ok "OS: ${NAME:-Unknown} ${VERSION_ID:-?} ($(uname -m))"
    [[ "${ID:-}" == "ubuntu" ]] || warn "Không phải Ubuntu — tiếp tục với rủi ro."

    # FIX: Xử lý root đúng — chỉ cần sudo khi chạy bằng user thường
    spin_start "Kiểm tra quyền thực thi..."
    sleep 0.2; spin_stop
    if [[ "${EUID}" -eq 0 ]]; then
        warn "Đang chạy với root. Script sẽ dùng trực tiếp không qua sudo."
    else
        sudo -v 2>/dev/null || die "Cần sudo để cài packages. Chạy: sudo -v"
        # Giữ sudo alive ngầm
        ( while true; do sudo -n true; sleep 50; done ) &
        _SUDO_KEEP=$!
    fi
    ok "Quyền thực thi: OK"

    # Internet
    spin_start "Kiểm tra kết nối internet..."
    curl -fsSL --max-time 8 https://github.com -o /dev/null 2>/dev/null \
        || die "Không thể kết nối GitHub. Kiểm tra mạng."
    spin_stop
    ok "Kết nối GitHub: OK"

    # Disk
    spin_start "Kiểm tra dung lượng..."
    local free_mb; free_mb=$(df -m "${HOME}" | awk 'NR==2{print $4}')
    spin_stop
    (( free_mb >= 500 )) || die "Không đủ dung lượng: ${free_mb}MB (cần >= 500MB)"
    ok "Dung lượng trống: ${free_mb}MB"
}

s2_packages() {
    step 2 ${TOTAL} "Cài đặt system packages"

    spin_start "apt-get update..."
    # FIX: dùng _sudo thay vì sudo cứng
    run "apt update" _sudo apt-get update -qq
    spin_stop; ok "Package index đã cập nhật."

    local pkgs=(
        build-essential cmake ninja-build git pkg-config wget curl
        libssl-dev openssl libcap-dev libcap2-bin libc6-dev
        binutils checksec clang-tidy cppcheck valgrind gdb
        lsb-release software-properties-common
        apt-transport-https ca-certificates gnupg
    )

    spin_start "Cài ${#pkgs[@]} packages..."
    run "apt install" _sudo apt-get install -y "${pkgs[@]}"
    spin_stop
    ok "System packages: OK"
}

s3_compiler() {
    step 3 ${TOTAL} "Compiler — GCC >= 12 (C++20)"

    if command -v g++ &>/dev/null; then
        local v; v=$(g++ -dumpversion | cut -d. -f1)
        if (( v >= GCC_MIN )); then
            ok "GCC ${v} — đạt yêu cầu."; return
        fi
        warn "GCC ${v} quá cũ (cần >= ${GCC_MIN})."
    else
        warn "GCC chưa được cài."
    fi

    spin_start "Thêm ubuntu-toolchain-r PPA..."
    run "add-apt-repository" _sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
    run "apt update" _sudo apt-get update -qq
    spin_stop; ok "PPA thêm xong."

    spin_start "Cài GCC ${GCC_MIN}..."
    run "install gcc" _sudo apt-get install -y "gcc-${GCC_MIN}" "g++-${GCC_MIN}"
    run "alt gcc" _sudo update-alternatives \
        --install /usr/bin/gcc gcc "/usr/bin/gcc-${GCC_MIN}" 100
    run "alt g++" _sudo update-alternatives \
        --install /usr/bin/g++ g++ "/usr/bin/g++-${GCC_MIN}" 100
    spin_stop
    ok "GCC ${GCC_MIN} đã cài và set mặc định."
}

s4_cmake() {
    step 4 ${TOTAL} "CMake >= 3.20"

    if command -v cmake &>/dev/null; then
        local ver; ver=$(cmake --version | grep -oP '\d+\.\d+' | head -1)
        local maj="${ver%%.*}" min="${ver##*.}"
        if (( maj > CMAKE_MIN_MAJ )) || \
           (( maj == CMAKE_MIN_MAJ && min >= CMAKE_MIN_MIN )); then
            ok "CMake ${ver} — đạt yêu cầu."; return
        fi
        warn "CMake ${ver} quá cũ."
    else
        warn "CMake chưa cài."
    fi

    spin_start "Thêm Kitware APT repo..."
    wget -qO- https://apt.kitware.com/keys/kitware-archive-latest.asc \
        | gpg --dearmor \
        | _sudo tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] \
https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main" \
        | _sudo tee /etc/apt/sources.list.d/kitware.list >/dev/null
    run "apt update" _sudo apt-get update -qq
    run "install cmake" _sudo apt-get install -y cmake
    spin_stop
    ok "CMake $(cmake --version | grep -oP '\d+\.\d+\.\d+' | head -1) đã cài."
}

s5_openssl() {
    step 5 ${TOTAL} "OpenSSL >= 3.0 (FIPS 140-3)"

    local ssl_ver; ssl_ver=$(openssl version 2>/dev/null | awk '{print $2}' || echo "0.0.0")
    local maj="${ssl_ver%%.*}"
    info "Phiên bản hiện tại: OpenSSL ${ssl_ver}"

    if (( maj >= OPENSSL_MIN )); then
        ok "OpenSSL ${ssl_ver} — đạt yêu cầu."
        pkg-config --exists libcrypto 2>/dev/null \
            && ok "libcrypto headers: OK" \
            || { run "install libssl-dev" _sudo apt-get install -y libssl-dev
                 ok "libssl-dev đã cài."; }
        return
    fi

    warn "OpenSSL ${ssl_ver} < 3.0 — Build từ source với enable-fips..."
    local VER="3.3.2"
    local PREFIX="/usr/local/openssl3"
    local TAR="/tmp/openssl-${VER}.tar.gz"

    spin_start "Tải OpenSSL ${VER}..."
    wget -q "https://www.openssl.org/source/openssl-${VER}.tar.gz" -O "${TAR}" \
        || die "Không tải được OpenSSL ${VER}."
    spin_stop; ok "OpenSSL ${VER} đã tải."

    spin_start "Configure OpenSSL (enable-fips)..."
    tar -xzf "${TAR}" -C /tmp
    cd "/tmp/openssl-${VER}"
    run "configure" ./Configure \
        --prefix="${PREFIX}" --openssldir="${PREFIX}/ssl" \
        linux-x86_64 no-shared enable-fips
    spin_stop; ok "Configure xong."

    spin_start "Build OpenSSL ($(nproc) cores)..."
    run "make openssl" make -j"$(nproc)"
    spin_stop; ok "Build xong."

    spin_start "Install OpenSSL..."
    run "install openssl" _sudo make install_sw install_ssldirs
    spin_stop

    export PKG_CONFIG_PATH="${PREFIX}/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
    export OPENSSL_ROOT_DIR="${PREFIX}"
    grep -qF "PKG_CONFIG_PATH=${PREFIX}/lib64/pkgconfig" ~/.bashrc 2>/dev/null \
        || echo "export PKG_CONFIG_PATH=${PREFIX}/lib64/pkgconfig:\${PKG_CONFIG_PATH}" \
           >> ~/.bashrc
    _sudo ldconfig >> "${LOG_FILE}" 2>&1 || true
    cd "${HOME}"
    ok "OpenSSL ${VER} cài tại ${PREFIX}."
}

s6_clone() {
    step 6 ${TOTAL} "Clone repository dainghiavn/C2plus"

    # FIX: Dùng thư mục tạm riêng, tránh đụng độ với lần chạy trước
    local CLONE_PARENT="/tmp/.secureapp_clone_$$"

    if [[ -d "${INSTALL_DIR}" ]]; then
        warn "${INSTALL_DIR} đã tồn tại."
        printf "  ${Y}Xoá và clone lại từ đầu? [y/N]:${NC} "
        read -r answer
        if [[ "${answer,,}" == "y" ]]; then
            spin_start "Xoá thư mục cũ..."
            rm -rf "${INSTALL_DIR}"
            spin_stop; ok "Đã xoá ${INSTALL_DIR}."
        else
            ok "Giữ nguyên ${INSTALL_DIR} — bỏ qua bước clone."
            return
        fi
    fi

    mkdir -p "${CLONE_PARENT}"

    spin_start "git clone github.com/dainghiavn/C2plus..."
    run "git clone" git clone --depth=1 "${REPO_CLONE}" "${CLONE_PARENT}/C2plus"
    spin_stop; ok "Clone xong."

    # FIX: Kiểm tra APP_SUBDIR tồn tại trong repo trước khi copy
    if [[ ! -d "${CLONE_PARENT}/C2plus/${APP_SUBDIR}" ]]; then
        die "Không tìm thấy thư mục '${APP_SUBDIR}' trong repo. Kiểm tra cấu trúc repo."
    fi

    spin_start "Thiết lập ${INSTALL_DIR}..."
    cp -r "${CLONE_PARENT}/C2plus/${APP_SUBDIR}" "${INSTALL_DIR}"
    rm -rf "${CLONE_PARENT}"
    spin_stop
    ok "Project tại: ${INSTALL_DIR}"
}

s7_runtime() {
    step 7 ${TOTAL} "Thiết lập môi trường runtime"

    # FIX: Lấy đúng username trong mọi tình huống (root, sudo, user thường)
    local UN
    UN=$(get_real_user)
    info "Runtime owner: ${UN}"

    spin_start "Tạo /var/log/secureapp & /etc/secureapp..."
    for d in /var/log/secureapp /etc/secureapp; do
        _sudo mkdir -p "${d}"
        _sudo chown "${UN}:${UN}" "${d}" 2>/dev/null \
            || _sudo chown "${UN}" "${d}" 2>/dev/null || true
        _sudo chmod 750 "${d}"
    done
    spin_stop; ok "Runtime dirs: OK"

    # Master key
    local KEY="/etc/secureapp/master.key"
    if [[ ! -f "${KEY}" ]]; then
        spin_start "Tạo master key 256-bit..."
        openssl rand -hex 32 | _sudo tee "${KEY}" >/dev/null
        _sudo chmod 400 "${KEY}"
        _sudo chown "${UN}" "${KEY}" 2>/dev/null || true
        spin_stop; ok "Master key: ${KEY} (mode 400)"
    else
        ok "Master key đã tồn tại: ${KEY}"
    fi

    # .env
    local ENV="${INSTALL_DIR}/.env"
    if [[ ! -f "${ENV}" ]]; then
        local SESSION_SECRET; SESSION_SECRET=$(openssl rand -hex 32)
        cat > "${ENV}" << ENVEOF
# SecureConsoleApp Environment
# WARNING: Không commit file này lên git!
export MASTER_KEY_PATH=/etc/secureapp/master.key
export AUDIT_LOG_PATH=/var/log/secureapp/audit.log
export SESSION_SECRET=${SESSION_SECRET}
export APP_ENV=production
ENVEOF
        chmod 600 "${ENV}"
        ok ".env tạo tại: ${ENV}"
    else
        ok ".env đã tồn tại."
    fi

    # .gitignore — FIX: chỉ append nếu chưa có
    local GI="${INSTALL_DIR}/.gitignore"
    touch "${GI}"
    grep -qxF ".env"    "${GI}" || echo ".env"    >> "${GI}"
    grep -qxF "build/"  "${GI}" || echo "build/"  >> "${GI}"
    grep -qxF "*.key"   "${GI}" || echo "*.key"   >> "${GI}"
    grep -qxF "*.log"   "${GI}" || echo "*.log"   >> "${GI}"
    ok ".gitignore cập nhật."

    # memlock
    local LC="/etc/security/limits.conf"
    if ! grep -q "${UN}.*memlock" "${LC}" 2>/dev/null; then
        echo "${UN} hard memlock unlimited" | _sudo tee -a "${LC}" >/dev/null
        echo "${UN} soft memlock unlimited" | _sudo tee -a "${LC}" >/dev/null
        ok "memlock unlimited: ${UN}"
    else
        ok "memlock đã cấu hình."
    fi
}

s8_build() {
    step 8 ${TOTAL} "Biên dịch dự án (Release + Debug)"

    # FIX: Kiểm tra đúng tên file — repo dùng CMakeLists.txt (có thể là .txt trên Windows)
    local CMAKEFILE
    if [[ -f "${INSTALL_DIR}/CMakeLists.txt" ]]; then
        CMAKEFILE="${INSTALL_DIR}/CMakeLists.txt"
    elif [[ -f "${INSTALL_DIR}/CMakeLists.txt" ]]; then
        CMAKEFILE="${INSTALL_DIR}/CMakeLists.txt"
    else
        die "CMakeLists.txt không tìm thấy tại ${INSTALL_DIR}/"
    fi
    info "Dùng: ${CMAKEFILE}"

    [[ -f "${INSTALL_DIR}/src/main.cpp" ]] \
        || die "src/main.cpp không tìm thấy tại ${INSTALL_DIR}/src/"

    local CMAKE_EXTRA=""
    [[ -n "${OPENSSL_ROOT_DIR:-}" ]] \
        && CMAKE_EXTRA="-DOPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}"

    # ── Release ──
    spin_start "Configure Release build..."
    run "cmake release config" \
        cmake -S "${INSTALL_DIR}" \
              -B "${INSTALL_DIR}/build/release" \
              -DCMAKE_BUILD_TYPE=Release \
              -G Ninja \
              ${CMAKE_EXTRA}
    spin_stop; ok "Release: configured."

    spin_start "Build Release ($(nproc) cores)..."
    run "cmake release build" \
        cmake --build "${INSTALL_DIR}/build/release" --parallel "$(nproc)"
    spin_stop; ok "Release: ${INSTALL_DIR}/build/release/SecureConsoleApp"

    # ── Debug ──
    spin_start "Configure Debug build (ASan + UBSan)..."
    run "cmake debug config" \
        cmake -S "${INSTALL_DIR}" \
              -B "${INSTALL_DIR}/build/debug" \
              -DCMAKE_BUILD_TYPE=Debug \
              -G Ninja \
              ${CMAKE_EXTRA}
    spin_stop; ok "Debug: configured."

    spin_start "Build Debug ($(nproc) cores)..."
    run "cmake debug build" \
        cmake --build "${INSTALL_DIR}/build/debug" --parallel "$(nproc)"
    spin_stop; ok "Debug: ${INSTALL_DIR}/build/debug/SecureConsoleApp"

    # ── Hardening check ──
    local BIN="${INSTALL_DIR}/build/release/SecureConsoleApp"
    info "Kiểm tra binary hardening..."
    if command -v checksec &>/dev/null; then
        checksec --file="${BIN}" 2>/dev/null \
            | while IFS= read -r line; do info "  ${line}"; done
    else
        file "${BIN}" | grep -q "pie executable" \
            && ok "  PIE: enabled"          || warn "  PIE: không tìm thấy"
        readelf -s "${BIN}" 2>/dev/null | grep -q "__stack_chk" \
            && ok "  Stack Canary: enabled" || warn "  Stack Canary: không tìm thấy"
        readelf -l "${BIN}" 2>/dev/null | grep -q "GNU_RELRO" \
            && ok "  RELRO: enabled"        || warn "  RELRO: không tìm thấy"
    fi

    # setcap — FIX: dùng _sudo
    _sudo setcap cap_ipc_lock=+ep "${BIN}" 2>/dev/null \
        && ok "cap_ipc_lock: granted (MemoryGuard/mlock)" \
        || warn "setcap thất bại — mlock bị giới hạn (không ảnh hưởng build)."
}

summary() {
    printf "\n  ${DIM}$(printf '═%.0s' {1..61})${NC}\n"
    printf "\n  ${G}${BOLD}✔  CÀI ĐẶT HOÀN TẤT — SecureConsoleApp v${APP_VERSION}${NC}\n\n"

    printf "  ${BOLD}Môi trường:${NC}\n"
    command -v g++     &>/dev/null && printf "  ${DIM}GCC     :${NC} $(g++ --version | head -1)\n"
    command -v cmake   &>/dev/null && printf "  ${DIM}CMake   :${NC} $(cmake --version | head -1)\n"
    command -v openssl &>/dev/null && printf "  ${DIM}OpenSSL :${NC} $(openssl version)\n"
    command -v ninja   &>/dev/null && printf "  ${DIM}Ninja   :${NC} v$(ninja --version)\n"

    printf "\n  ${BOLD}Chạy ứng dụng:${NC}\n"
    printf "  ${C}source ${INSTALL_DIR}/.env${NC}\n"
    printf "  ${C}${INSTALL_DIR}/build/release/SecureConsoleApp${NC}\n"

    printf "\n  ${BOLD}Rebuild sau khi sửa code:${NC}\n"
    printf "  ${DIM}cmake --build ${INSTALL_DIR}/build/release --parallel \$(nproc)${NC}\n"

    printf "\n  ${Y}⚠  Bảo mật:${NC}\n"
    printf "  ${DIM}• Không commit .env / *.key lên git${NC}\n"
    printf "  ${DIM}• Không chạy binary với sudo${NC}\n"
    printf "  ${DIM}• Dùng setcap cho capabilities (principle of least privilege)${NC}\n"

    printf "\n  ${DIM}Log đầy đủ: ${LOG_FILE}${NC}\n"
    printf "  ${DIM}$(printf '═%.0s' {1..61})${NC}\n\n"
}

# ── CLEANUP ───────────────────────────────────────────────────────────────────
# FIX: Khởi tạo _SUDO_KEEP="" để tránh "unbound variable" khi chạy với root
_SUDO_KEEP=""

cleanup() {
    spin_stop
    [[ -n "${_SUDO_KEEP}" ]] && kill "${_SUDO_KEEP}" 2>/dev/null || true
    printf "${SHOW}"
}
trap cleanup EXIT INT TERM

# ── MAIN ──────────────────────────────────────────────────────────────────────
main() {
    touch "${LOG_FILE}"
    banner
    _log "=== SecureConsoleApp Installer v${APP_VERSION} | $(date) ==="
    _log "=== EUID=${EUID} HOME=${HOME} ==="
    s1_preflight
    s2_packages
    s3_compiler
    s4_cmake
    s5_openssl
    s6_clone
    s7_runtime
    s8_build
    summary
}

main "$@"
