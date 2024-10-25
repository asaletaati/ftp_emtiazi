cmake_minimum_required(VERSION 3.10)
project(FTPServer)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR})

# Source files
set(SOURCES src/main.cpp)

# Create the executable
add_executable(ftp_server ${SOURCES})

# Link OpenSSL libraries
target_link_libraries(ftp_server ${OPENSSL_LIBRARIES})
