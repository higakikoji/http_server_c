cmake_minimum_required(VERSION 3.26.5)
project(http_server_c C)
set(CMAKE_C_FLAGS "-DENABLE_SSL")
add_executable(http_server_c main.c)
target_link_libraries(http_server_c ssl crypto)
