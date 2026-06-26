cmake_minimum_required(VERSION 3.16)
project(ShieldWall VERSION 1.0.0 LANGUAGES CXX)

# ─── C++ Standard ────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Build type defaults ──────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ─── Compiler flags ───────────────────────────────────────────────────────────
if(MSVC)
  add_compile_options(/W4 /WX- /MP /permissive-)
  # MSVC: enable structured exception handling for std::regex et al.
  add_compile_options(/EHsc)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -fno-strict-aliasing)
  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3 -march=native)
  endif()
endif()

# ─── Include directories ──────────────────────────────────────────────────────
include_directories(
  ${CMAKE_SOURCE_DIR}/src/core
  ${CMAKE_SOURCE_DIR}/src/modules
)

# ─── Core library ────────────────────────────────────────────────────────────
add_library(shieldwall_core STATIC
  # Core
  src/core/WafEngine.cpp
  src/core/AhoCorasick.cpp
  src/core/RuleParser.cpp
  src/core/RuleMatcher.cpp
  src/core/ReconTracker.cpp

  # Modules
  src/modules/AnomalyDetector.cpp
  src/modules/SmartAnomalyDetector.cpp
  src/modules/BruteForceGuard.cpp
  src/modules/RateLimiter.cpp
  src/modules/DdosProtector.cpp
)

target_include_directories(shieldwall_core PUBLIC
  ${CMAKE_SOURCE_DIR}/src/core
  ${CMAKE_SOURCE_DIR}/src/modules
)

# ─── Threading ───────────────────────────────────────────────────────────────
find_package(Threads REQUIRED)
target_link_libraries(shieldwall_core PUBLIC Threads::Threads)

# ─── Optional: standalone test executable ────────────────────────────────────
# Uncomment once tests/main_test.cpp exists:
# add_executable(shieldwall_test tests/main_test.cpp)
# target_link_libraries(shieldwall_test PRIVATE shieldwall_core)

# ─── Install ─────────────────────────────────────────────────────────────────
install(TARGETS shieldwall_core
        ARCHIVE DESTINATION lib)
install(DIRECTORY src/core/   DESTINATION include/shieldwall FILES_MATCHING PATTERN "*.hpp")
install(DIRECTORY src/modules/ DESTINATION include/shieldwall FILES_MATCHING PATTERN "*.hpp")

message(STATUS "ShieldWall C++ WAF Engine — Build type: ${CMAKE_BUILD_TYPE}")
