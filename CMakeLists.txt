cmake_minimum_required(VERSION 3.10)
project(socket CXX)

set(CMAKE_CXX_STANDARD 17)

add_executable(xshd xshd.cpp protocol.cpp secure_channel.cpp shell_exec.cpp)
add_executable(xsh xsh.cpp protocol.cpp secure_channel.cpp shell_exec.cpp)
add_executable(xcp xcp.cpp protocol.cpp secure_channel.cpp)

find_package(glog REQUIRED)
target_link_libraries(xshd PRIVATE glog::glog)
target_link_libraries(xsh PRIVATE glog::glog)
target_link_libraries(xcp PRIVATE glog::glog)

find_package(nlohmann_json 3 REQUIRED)

find_package(OpenSSL REQUIRED)
target_link_libraries(xshd PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(xsh PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(xcp PRIVATE OpenSSL::SSL OpenSSL::Crypto)
