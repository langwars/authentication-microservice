cmake_minimum_required(VERSION 3.10)
project(auth_service)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

# Add compiler optimizations
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native")

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

# Add include directories
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(/opt/homebrew/include)
include_directories(${Boost_INCLUDE_DIRS})

# Add executable
add_executable(auth_service 
    src/main.cpp
    src/jwt.cpp
    src/user_store.cpp
    src/crypto.cpp
)

# Link libraries
target_link_libraries(auth_service
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    Boost::system
)
