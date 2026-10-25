cmake_minimum_required(VERSION 3.20)
project(sentinel_capture VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(SENTINEL_BUILD_TESTS "Build the unit and fixture tests" ON)
option(SENTINEL_SANITIZE "Build with AddressSanitizer and UBSan" OFF)
# CI (GitHub Actions sets CI=true) builds with warnings as errors.
if(DEFINED ENV{CI})
  set(_werror_default ON)
else()
  set(_werror_default OFF)
endif()
option(SENTINEL_WERROR "Treat compiler warnings as errors" ${_werror_default})

# --- dependencies -----------------------------------------------------------

include(FetchContent)

# nlohmann/json, pinned release tarball (headers + CMake config only).
FetchContent_Declare(nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
  URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(nlohmann_json)

# libpcap: pkg-config on Linux (libpcap-dev); the macOS SDK ships no .pc file,
# so fall back to a plain header/library search.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(PCAP QUIET IMPORTED_TARGET libpcap)
endif()
if(TARGET PkgConfig::PCAP)
  add_library(sentinel_pcap ALIAS PkgConfig::PCAP)
else()
  find_path(PCAP_INCLUDE_DIR pcap/pcap.h REQUIRED)
  find_library(PCAP_LIBRARY NAMES pcap REQUIRED)
  add_library(sentinel_pcap INTERFACE)
  target_include_directories(sentinel_pcap INTERFACE ${PCAP_INCLUDE_DIR})
  target_link_libraries(sentinel_pcap INTERFACE ${PCAP_LIBRARY})
endif()

# --- warnings, applied to our targets only ----------------------------------

add_library(sentinel_warnings INTERFACE)
target_compile_options(sentinel_warnings INTERFACE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
  $<$<BOOL:${SENTINEL_WERROR}>:-Werror>)
if(SENTINEL_SANITIZE)
  target_compile_options(sentinel_warnings INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(sentinel_warnings INTERFACE -fsanitize=address,undefined)
endif()

# --- core library + binary --------------------------------------------------

add_library(sentinel_core STATIC
  src/addresses.cpp
  src/capture_runner.cpp
  src/config.cpp
  src/log.cpp
  src/packet_parser.cpp
  src/pcap_handle.cpp
  src/window_aggregator.cpp
  src/window_clock.cpp
  src/window_writer.cpp)
target_include_directories(sentinel_core PUBLIC src)
target_link_libraries(sentinel_core
  PUBLIC sentinel_pcap
  PRIVATE nlohmann_json::nlohmann_json sentinel_warnings)

add_executable(sentinel-capture src/main.cpp)
target_link_libraries(sentinel-capture PRIVATE sentinel_core sentinel_warnings)

include(GNUInstallDirs)
install(TARGETS sentinel-capture RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# --- tests ------------------------------------------------------------------

if(SENTINEL_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
