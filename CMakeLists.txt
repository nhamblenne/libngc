#######################################################################
# CMakeLists.txt
# Copyright (c) 2020 Nicolas Ivan Hamblenne
#######################################################################

cmake_minimum_required(VERSION 3.5)
project(libngc C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_DEBUG_POSTFIX _g)

option(DevMode "Development mode" OFF)
string(REGEX REPLACE "(.*)/[^/]*" "\\1" DEV_ROOT "${PROJECT_SOURCE_DIR}")
string(REGEX REPLACE ".*/([^/]*)" "\\1" PROJECT_BASE_NAME "${PROJECT_SOURCE_DIR}")
if(DevMode)
    set(CMAKE_INSTALL_PREFIX "${DEV_ROOT}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
else()
    if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set(CMAKE_INSTALL_PREFIX "/opt/nih" CACHE PATH "Install prefix" FORCE)
    endif()
endif()

add_subdirectory(src)
if(DevMode)
    add_subdirectory(tests)
endif()
