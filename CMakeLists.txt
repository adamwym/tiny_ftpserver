cmake_minimum_required(VERSION 3.7)
project(tiny_ftpserver)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp session.h session.cpp ftp_def.h fd_transfer.h fd_transfer.cpp)

add_executable(tiny_ftpserver ${SOURCE_FILES})
add_executable(tiny_test test.cpp)
add_definitions(-std=c++11)
target_link_libraries(tiny_ftpserver crypt)
