cmake_minimum_required(VERSION 3.10)
project(dnsrelay C)

set(CMAKE_C_STANDARD 99)

add_executable(dnsrelay main.c table.c protocol.c util.c server.c cache.c)

# Windows下需要链接ws2_32库
if (WIN32)
    target_link_libraries(dnsrelay ws2_32)
endif()
