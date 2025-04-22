cmake_minimum_required(VERSION 3.16)

project(bridge LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/wintun ${CMAKE_CURRENT_SOURCE_DIR}/IP)

add_executable(bridge
  main.cpp
  wintun/wintunlib.h
  wintun/wintunlib.cpp
  killer.h
  BridgeData.h
  routetable.h routetable.cpp
  IP/protocol.h
  IP/protocol.cpp
  receiver.h receiver.cpp
)
target_link_libraries(bridge Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::Network Iphlpapi.lib Ws2_32.lib)

include(GNUInstallDirs)
install(TARGETS bridge
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
