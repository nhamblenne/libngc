#######################################################################
# tests/CMakeLists.txt
# Copyright (c) 2020 Nicolas Ivan Hamblenne
#######################################################################

add_executable(test1 test1.c)
target_link_libraries(test1 ngc)
add_test(NAME test1
        COMMAND ntt -v -d ${CMAKE_CURRENT_LIST_DIR} $<TARGET_FILE:test1>)

add_executable(test2 test2.c)
target_link_libraries(test2 ngc)
add_test(NAME test2
        COMMAND ntt -v -d ${CMAKE_CURRENT_LIST_DIR} $<TARGET_FILE:test2>)

add_executable(test3 test3.c)
target_link_libraries(test3 ngc)
add_test(NAME test3
        COMMAND ntt -v -d ${CMAKE_CURRENT_LIST_DIR} $<TARGET_FILE:test3>)

add_executable(test4 test4.c)
target_link_libraries(test4 ngc)
add_test(NAME test4
        COMMAND ntt -v -d ${CMAKE_CURRENT_LIST_DIR} $<TARGET_FILE:test4>)
