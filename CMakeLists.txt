#
#   Main CMakeLists.txt
#       - Build application, lib, dependencies
#
CMAKE_MINIMUM_REQUIRED(VERSION 3.10.0)

PROJECT(dhcp_server)


# Linux
set(CMAKE_SKIP_BUILD_RPATH  FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH "./")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

ADD_SUBDIRECTORY(src/)



