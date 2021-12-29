#######################################################################
# CMakeLists.txt
# Copyright (c) 2020 -- 2021 Nicolas Ivan Hamblenne
#######################################################################

cmake_minimum_required(VERSION 3.7)
project(libngc LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_DEBUG_POSTFIX _g)

option(DevMode "Development mode" OFF)

if(DevMode)
    if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
        if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
            string(REGEX REPLACE "(.*)/[^/]*" "\\1" DEV_ROOT "${CMAKE_SOURCE_DIR}")
            set(CMAKE_INSTALL_PREFIX "${DEV_ROOT}" CACHE PATH "Install prefix" FORCE)
        endif()

        option(TEST_LIBNGC "Testing libngc" ON)
    else()
        option(TEST_LIBNGC "Testing libngc" OFF)
    endif()

    include(cmake/CompilerWarnings.cmake)
else()
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT AND CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
        set(CMAKE_INSTALL_PREFIX "/opt/nih" CACHE PATH "Install prefix" FORCE)
    endif()

    option(TEST_LIBNGC "Testing libngc" OFF)

    function(set_project_warnings project_name kind)
    endfunction()
endif()

add_subdirectory(src)

if(TEST_LIBNGC)
    enable_testing()
    add_subdirectory(tests)
endif()
