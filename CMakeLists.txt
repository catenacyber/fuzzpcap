cmake_minimum_required (VERSION 3.0)

project (fuzzpcap C)
set(FUZZPCAP_MAJOR_VERSION 0)
set(FUZZPCAP_MINOR_VERSION 1)
set(FUZZPCAP_MICRO_VERSION 0)
set(FUZZPCAP_VERSION ${FUZZPCAP_MAJOR_VERSION}.${FUZZPCAP_MINOR_VERSION}.${FUZZPCAP_MICRO_VERSION})

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -DDEBUG")

find_library(PCAP_LIB pcap)

set(fuzzpcap_src fuzz_pcap.c)
set(fuzzpcap_hdr fuzz_pcap.h)

add_library(fuzzpcap STATIC ${fuzzpcap_src} ${fuzzpcap_hdr})
set_target_properties(fuzzpcap PROPERTIES PUBLIC_HEADER ${fuzzpcap_hdr})

set(fuzzpcap_libs "${PCAP_LIB}" fuzzpcap)

set(fpc_bin_src main.c)

add_executable (fpc_bin ${fpc_bin_src})
target_link_libraries (fpc_bin ${fuzzpcap_libs})

install(TARGETS fuzzpcap fpc_bin)