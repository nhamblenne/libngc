add_executable(test1 test1.c)
target_link_libraries(test1 ngc)
target_include_directories(test1 PRIVATE "${PROJECT_SOURCE_DIR}/src")
