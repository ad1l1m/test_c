cmake_minimum_required(VERSION 3.10)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})

add_executable(sniffer
    src/main.cpp
    src/sniffer.cpp
)

target_link_libraries(sniffer ${PCAP_LIBRARIES})