cmake_minimum_required(VERSION 3.16)

project(bridge LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../common/wintun ${CMAKE_CURRENT_SOURCE_DIR}/../common ${CMAKE_CURRENT_SOURCE_DIR}/../common/Npcap)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../common/Npcap)

add_executable(bridge
  main.cpp
  ../common/wintun/wintunlib.h
  ../common/wintun/wintunlib.cpp
  ../common/killer.h
  BridgeData.h
  routetable.h routetable.cpp
  ../common/protocol.h
  ../common/protocol.cpp
  ../common/adapteraddr.h
  ../common/adapteraddr.cpp
  receiver.h receiver.cpp
)
target_link_libraries(bridge Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network Iphlpapi.lib Ws2_32.lib wpcap.lib)

include(GNUInstallDirs)
install(TARGETS bridge
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
