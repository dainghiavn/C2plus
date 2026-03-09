cmake_minimum_required(VERSION 3.20)
project(SecureConsoleApp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Security Compiler Flags ──
if (MSVC)
    add_compile_options(
        /W4 /WX /GS /DYNAMICBASE /NXCOMPAT
        /sdl /guard:cf /Qspectre
    )
    add_link_options(/LTCG /OPT:REF /OPT:ICF)
else()
    add_compile_options(
        -Wall -Wextra -Werror
        -Wformat=2
        -Wstack-protector
        -Warray-bounds=2
        -fstack-protector-strong
        -fstack-clash-protection
        -D_FORTIFY_SOURCE=3
        -fPIE
        -fcf-protection=full
    )
    add_link_options(
        -pie
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack
    )
endif()

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

# Framework is header-only: only compile main.cpp
add_executable(${PROJECT_NAME} src/main.cpp)

target_include_directories(${PROJECT_NAME} PRIVATE include)

target_link_libraries(${PROJECT_NAME} PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Debug: AddressSanitizer + UBSan + LeakSanitizer
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    if (NOT MSVC)
        target_compile_options(${PROJECT_NAME} PRIVATE
            -fsanitize=address,undefined,leak -g -O0)
        target_link_options(${PROJECT_NAME} PRIVATE
            -fsanitize=address,undefined,leak)
    endif()
endif()

# Release: LTO + strip
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    if (NOT MSVC)
        target_compile_options(${PROJECT_NAME} PRIVATE -O2 -flto)
        target_link_options(${PROJECT_NAME} PRIVATE -flto -s)
    endif()
endif()
