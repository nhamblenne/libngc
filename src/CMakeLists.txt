set(HEADERS ngc.h)
add_library(ngc ngc.c)
target_include_directories(ngc PUBLIC "${CMAKE_INSTALL_PREFIX}/include")

install(TARGETS ngc EXPORT libngcConfig DESTINATION lib)
install(FILES ${HEADERS} DESTINATION include)
install(EXPORT libngcConfig DESTINATION lib/cmake/libngc)
