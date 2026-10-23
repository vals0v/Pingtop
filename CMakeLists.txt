cmake_minimum_required(VERSION 3.20)
project(pingtop
    VERSION 1.0.0
    DESCRIPTION "Interactive cross-platform TUI monitor for network latency and quality"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_executable(pingtop
    src/main.cpp
    src/icmp_socket.cpp
    src/net_discovery.cpp
    src/network_monitor.cpp
    src/tui_renderer.cpp
)

target_include_directories(pingtop PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(pingtop PRIVATE /W4 /permissive-)
else()
    target_compile_options(pingtop PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Woverloaded-virtual
    )
endif()

option(PINGTOP_STATIC_LIBCXX "Link libstdc++/libc++ statically on Linux" OFF)
if(PINGTOP_STATIC_LIBCXX AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(pingtop PRIVATE -static-libgcc -static-libstdc++)
endif()

install(TARGETS pingtop RUNTIME DESTINATION bin)
