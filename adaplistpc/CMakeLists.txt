cmake_minimum_required(VERSION 3.16)

project(adaplistpc LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories("C:/Program Files/Npcap/include")
link_directories("C:/Program Files/Npcap/lib/x64")

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

add_executable(adaplistpc
  main.cpp
)
target_link_libraries(adaplistpc Qt${QT_VERSION_MAJOR}::Core wpcap Ws2_32)

include(GNUInstallDirs)
install(TARGETS adaplistpc
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
