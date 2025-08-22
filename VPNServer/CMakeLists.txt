cmake_minimum_required(VERSION 3.16)
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)

project(VPNServer LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (UNIX)
  if (FROM_DOCKER)
      set(CMAKE_PREFIX_PATH "/Qt/6.9.1/gcc_64")
    else()
      set(CMAKE_PREFIX_PATH "~/Qt/6.9.1/gcc_64")
    endif()
    ## message(STATUS "CMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH} la=${CMAKE_LIBRARY_ARCHITECTURE}")
endif()

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network)

if (WIN32)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common ${CMAKE_CURRENT_SOURCE_DIR}/../common/Npcap)
  link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../common/Npcap) #/usr/lib/gcc/x86_64-linux-gnu/13)
elseif(UNIX)
  find_library(PCAP_LIBRARY pcap REQUIRED)
  find_path(PCAP_INCLUDE_DIR pcap.h REQUIRED)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common ${PCAP_INCLUDE_DIR})
endif()

add_executable(VPNServer
  main.cpp
  server.h
  server.cpp
  ServerData.h
  handlers.h
  handlers.cpp
  ../common/protocol.h
  ../common/protocol.cpp
  ../common/ProtoBuilder.h
  ../common/ProtoBuilder.cpp
  ../common/adapteraddr.h
  ../common/adapteraddr.cpp
  ../common/rawsocket.h
  ../common/rawsocket.cpp
  ../common/dummysocket.h
  ../common/dummysocket.cpp
  ../common/ringbuffer.h
  ../common/ringbuffer.cpp
  ../common/inputreader.h
  ../common/inputreader.cpp
)

if (WIN32)
  target_compile_definitions(VPNServer PRIVATE _USE_PCAP_=1)
endif()

if (UNIX)
  target_compile_definitions(VPNServer PRIVATE _USE_NFQ_=1)
endif()


set(CMAKE_FIND_STATIC_PREFERENCES "STATIC")
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -Wl,--trace")

if (WIN32)
  target_link_libraries(VPNServer Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network Ws2_32.lib Iphlpapi.lib wpcap.lib)
elseif (UNIX)
  target_link_libraries(VPNServer Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network ${PCAP_LIBRARY} netfilter_queue)
endif()

include(GNUInstallDirs)
install(TARGETS VPNServer
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
