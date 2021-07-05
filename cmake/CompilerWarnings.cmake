# After Jason Turner's https://github.com/lefticus/cpp_starter_project

function(set_project_warnings project_name kind)
  option(WARNINGS_AS_ERRORS "Treat compiler warnings as errors" TRUE)

  set(CLANG_WARNINGS
      -Wall
      -Wextra # reasonable and standard
      -Wshadow # warn the user if a variable declaration shadows one from a parent context
      -Wcast-align # warn for potential performance problem casts
      -Wunused # warn on anything being unused
      -Wpedantic # warn if non-standard C++ is used
      -Wconversion # warn on type conversions that may lose data
      -Wsign-conversion # warn on sign conversions
      -Wnull-dereference # warn if a null dereference is detected
      -Wformat=2 # warn on security issues around functions that format output (ie printf)
  )

  set(GCC_WARNINGS
          ${CLANG_WARNINGS}
          -Wmisleading-indentation # warn if indentation implies blocks where blocks do not exist
          -Wduplicated-cond # warn if if / else chain has duplicated conditions
          -Wduplicated-branches # warn if if / else branches have duplicated code
          -Wlogical-op # warn about logical operations being used where bitwise were probably wanted
          )

  set(SUNPRO_WARNINGS
          -errtags)

  if(WARNINGS_AS_ERRORS)
    set(CLANG_WARNINGS ${CLANG_WARNINGS} -Werror)
    set(GCC_WARNINGS ${GCC_WARNINGS} -Werror)
    set(SUNPRO_WARNINGS ${SUNPRO_WARNINGS} -errwarn)
  endif()


  if(CMAKE_C_COMPILER_ID MATCHES ".*Clang")
    set(PROJECT_WARNINGS ${CLANG_WARNINGS})
  elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(PROJECT_WARNINGS ${GCC_WARNINGS})
  elseif(CMAKE_C_COMPILER_ID STREQUAL "SunPro")
    set(PROJECT_WARNINGS ${SUNPRO_WARNINGS})
  else()
    message(AUTHOR_WARNING "No compiler warnings set for '${CMAKE_C_COMPILER_ID}' compiler.")
  endif()

  target_compile_options(${project_name} ${kind} ${PROJECT_WARNINGS})

endfunction()
