cmake_minimum_required(VERSION 3.16)
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)

project(VPNServer LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network)

if (WIN32)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common ${CMAKE_CURRENT_SOURCE_DIR}/../common/Npcap)
  link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../common/Npcap)
elseif(UNIX)
  find_library(PCAP_LIBRARY pcap REQUIRED)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common ${PCAP_LIBRARY})
endif()

add_executable(VPNServer
  main.cpp
  ServerData.h
  handlers.h
  handlers.cpp
  ../common/protocol.h
  ../common/protocol.cpp
  ../common/ProtoBuilder.h
  ../common/ProtoBuilder.cpp
  ../common/adapteraddr.h
  ../common/adapteraddr.cpp
)

if (WIN32)
  target_link_libraries(VPNServer Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network Ws2_32.lib Iphlpapi.lib wpcap.lib)
elseif (UNIX)
  target_link_libraries(VPNServer Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network ${PCAP_LIBRARY})
endif()

include(GNUInstallDirs)
install(TARGETS VPNServer
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
