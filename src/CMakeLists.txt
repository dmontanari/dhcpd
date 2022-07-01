# Application build process

set(CMAKE_C_STANDARD 99)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/)
FILE(GLOB app_src ${CMAKE_SOURCE_DIR}/src/*.c)
FILE(GLOB app_headers ${CMAKE_SOURCE_DIR}/application/src/*.h)

add_executable(dhcp_server ${app_src} ${app_headers})

set(APPLICATION_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR} CACHE STRING "Directory for install application")

