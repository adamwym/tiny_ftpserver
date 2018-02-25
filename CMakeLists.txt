cmake_minimum_required(VERSION 3.0)
project(tiny_ftpserver)

set(CMAKE_CXX_STANDARD 11)
add_definitions(-std=c++11)
execute_process(COMMAND pkg-config --cflags glib-2.0 OUTPUT_VARIABLE GLIB_INCLUDE)
add_definitions(${GLIB_INCLUDE})


set(SOURCE_FILES main.cpp session.h session.cpp ftp_def.h fd_transfer.h fd_transfer.cpp parse_conf.h parse_conf.cpp ls.h ls.cpp log.h log.cpp utility.h utility.cpp)

add_executable(tiny_ftpserver ${SOURCE_FILES})
target_link_libraries(tiny_ftpserver crypt glib-2.0 ssl)

add_executable(tiny_ftpserver_daemon ${SOURCE_FILES})
target_link_libraries(tiny_ftpserver_daemon crypt glib-2.0 ssl)
target_compile_options(tiny_ftpserver_daemon PUBLIC -DRUN_AS_DAEMON)
set_target_properties(tiny_ftpserver_daemon PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/daemon)


