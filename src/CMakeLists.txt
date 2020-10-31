#######################################################################
# src/CMakeLists.txt
# Copyright (c) 2020 Nicolas Ivan Hamblenne
#######################################################################

set(HEADERS ngc.h)
add_library(ngc ngc.c)
target_include_directories(ngc INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>)
install(TARGETS ngc EXPORT libngcConfig DESTINATION lib)
install(FILES ${HEADERS} DESTINATION include)
install(EXPORT libngcConfig DESTINATION lib/cmake/libngc)
