cmake_minimum_required(VERSION 3.16)
project(submissiona_helib_terminal_core LANGUAGES CXX)
find_package(helib REQUIRED)
add_executable(helib_terminal_core terminal_core.cpp)
target_compile_features(helib_terminal_core PRIVATE cxx_std_17)
target_compile_options(helib_terminal_core PRIVATE -Wall -Wextra -Werror)
target_include_directories(helib_terminal_core PRIVATE
  ../../../../Code/third_party/helib-2.3.0/dependencies/json)
target_link_libraries(helib_terminal_core PRIVATE helib)
