cmake_minimum_required(VERSION 3.16)

project(VPNClient LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../common ${CMAKE_CURRENT_SOURCE_DIR}/../common/wintun)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../common/Npcap)

add_executable(VPNClient
  main.cpp
  ClientData.h
  handlers.h
  handlers.cpp
  routetable.h
  routetable.cpp
  ../common/killer.h
  ../common/wintun/wintunlib.h
  ../common/wintun/wintunlib.cpp
  ../common/protocol.h
  ../common/protocol.cpp
  ../common/ProtoBuilder.h
  ../common/ProtoBuilder.cpp
  ../common/adapteraddr.h
  ../common/adapteraddr.cpp
  ../common/ringbuffer.h
  ../common/ringbuffer.cpp
  ../common/inputreader.h
  ../common/inputreader.cpp
)

target_link_libraries(VPNClient Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network  Ws2_32.lib Iphlpapi.lib wpcap.lib)

include(GNUInstallDirs)
install(TARGETS VPNClient
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
