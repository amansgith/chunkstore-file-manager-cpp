cmake_minimum_required(VERSION 3.15)
project(FileManager)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use vcpkg if available
if(DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "")
endif()

# Find packages
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

# Define CPPHTTPLIB_OPENSSL_SUPPORT
add_definitions(-DCPPHTTPLIB_OPENSSL_SUPPORT)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Explicitly list source files
set(SOURCES
    src/main.cpp
    src/FileManager.cpp
    src/ThreadPool.cpp
)

# Add executable
add_executable(file_manager ${SOURCES})

# Link libraries
target_link_libraries(file_manager PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ws2_32
)

# Set include directories for target
target_include_directories(file_manager PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)