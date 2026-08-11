cmake_minimum_required(VERSION 3.10)
project(socket CXX)

set(CMAKE_CXX_STANDARD 17)

add_executable(server server.cpp protocol.cpp secure_channel.cpp shell_exec.cpp)
add_executable(client client.cpp protocol.cpp secure_channel.cpp shell_exec.cpp)

find_package(glog REQUIRED)
target_link_libraries(server PRIVATE glog::glog)
target_link_libraries(client PRIVATE glog::glog)

find_package(nlohmann_json 3 REQUIRED)

find_package(OpenSSL REQUIRED)
target_link_libraries(server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(client PRIVATE OpenSSL::SSL OpenSSL::Crypto)
