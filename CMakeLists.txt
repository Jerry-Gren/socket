cmake_minimum_required(VERSION 3.10)
project(socket CXX)

set(CMAKE_CXX_STANDARD 17)

add_executable(server server.cpp)
add_executable(client client.cpp)

find_package(glog REQUIRED)
target_link_libraries(server PRIVATE glog::glog)
target_link_libraries(client PRIVATE glog::glog)