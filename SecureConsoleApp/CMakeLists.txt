cmake_minimum_required(VERSION 3.20)
project(SecureConsoleApp VERSION 1.0.0 LANGUAGES CXX)

# ── C++20 Standard ──
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# FIX [G]: Export compile commands for clang-tidy / IDE integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Dependencies ──
find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

# ── Main Target ──
add_executable(${PROJECT_NAME} src/main.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE include)

# FIX [E]: Remove OpenSSL::SSL — project only uses libcrypto (AES, PBKDF2, HMAC, RAND)
target_link_libraries(${PROJECT_NAME} PRIVATE
    OpenSSL::Crypto
    Threads::Threads
)

# FIX [B]: Security flags scoped to target (not global add_compile_options)
# FIX [F]: Platform guards for compiler/linker-specific flags
if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4 /WX
        /GS           # Buffer security checks
        /GL           # FIX [D]: Whole-program optimization (required for /LTCG)
        /DYNAMICBASE  # ASLR
        /NXCOMPAT     # DEP
        /sdl          # Additional SDL checks
        /guard:cf     # Control Flow Guard
        /Qspectre     # Spectre mitigations
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        /LTCG         # Link-Time Code Generation (pairs with /GL)
        /OPT:REF      # Remove unreferenced functions/data
        /OPT:ICF      # Identical COMDAT folding
    )
else()
    # ── Flags supported by both GCC and Clang ──
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall -Wextra -Werror
        -Wformat=2
        -Wstack-protector
        -fstack-protector-strong
        -fPIE
    )

    # FIX [F]: GCC-only flags
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${PROJECT_NAME} PRIVATE
            -Warray-bounds=2         # GCC: =2 enables stricter checks; Clang uses plain -Warray-bounds
            -fstack-clash-protection # GCC 8+; not available on Apple Clang
        )
    endif()

    # FIX [F]: Clang-only flags
    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${PROJECT_NAME} PRIVATE
            -Warray-bounds           # Clang variant (no =2)
        )
    endif()

    # FIX [F]: x86/x86_64 only (Control-Flow Enforcement Technology)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|i[3-6]86|AMD64")
        target_compile_options(${PROJECT_NAME} PRIVATE
            -fcf-protection=full
        )
    endif()

    # FIX [F]: Linux GNU ld only (not macOS, not lld by default)
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(${PROJECT_NAME} PRIVATE
            -pie
            -Wl,-z,relro             # Read-only relocations
            -Wl,-z,now               # Resolve all symbols at load (full RELRO)
            -Wl,-z,noexecstack       # Non-executable stack
        )
    elseif (APPLE)
        target_link_options(${PROJECT_NAME} PRIVATE
            -pie
        )
    else()
        target_link_options(${PROJECT_NAME} PRIVATE -pie)
    endif()
endif()

# ── _FORTIFY_SOURCE: only when optimization is active ──
# FIX: Do NOT inject _FORTIFY_SOURCE globally — let each config handle it
# Debug: no FORTIFY (incompatible with -O0 on some compilers/warnings)
# Release/RelWithDebInfo: FORTIFY=3 (requires -O1+)
# FIX [C]: Use generator expressions instead of CMAKE_BUILD_TYPE string compare
#          Works correctly with multi-config generators (VS, Xcode, Ninja Multi-Config)
if (NOT MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=3>
        $<$<CONFIG:RelWithDebInfo>:-D_FORTIFY_SOURCE=2>
    )
endif()

# ── Debug: Sanitizers ──
# FIX [C]: Use generator expressions
if (NOT MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined,leak>
        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Debug>:-fno-omit-frame-pointer>   # Better ASan stack traces
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined,leak>
    )
endif()

# ── Release: LTO + strip ──
# FIX [A]: Remove -O2 — CMake Release already injects -O3 -DNDEBUG
#          Setting -O2 here conflicts with CMake's -O3 (last flag wins in GCC → -O2 downgrade)
# FIX [C]: Use generator expressions
if (NOT MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:-flto>
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:-flto>
        $<$<CONFIG:Release>:-s>     # Strip symbols
    )
endif()

# ── RelWithDebInfo: LTO with debug info, no strip ──
if (NOT MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:RelWithDebInfo>:-flto>
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:RelWithDebInfo>:-flto>
    )
endif()
