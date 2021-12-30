#######################################################################
# src/CMakeLists.txt
# Copyright (c) 2020 -- 2021  Nicolas Ivan Hamblenne
#######################################################################

set(HEADERS ngc.h)
add_library(ngc ngc.c)
set_project_warnings(ngc PRIVATE)
target_include_directories(ngc INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>)

if(LIBNGC_INSTALL)
    install(TARGETS ngc EXPORT libngcConfig DESTINATION lib)
    install(FILES ${HEADERS} DESTINATION include)
    install(EXPORT libngcConfig DESTINATION lib/cmake/libngc)
endif()
