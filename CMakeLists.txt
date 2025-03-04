cmake_minimum_required(VERSION 3.10)
project(hw1 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
include_directories(include test/inputs)


add_executable(hw2_main src/hw2.c src/hw2_main.c)
target_compile_options(hw2_main PUBLIC -Wall -Wextra -Wshadow -Wpedantic -Wdouble-promotion -Wformat=2 -Wundef -Werror -Wcast-align=strict)
target_link_libraries(hw2_main PUBLIC m)

add_executable(part1 src/hw2.c tests/src/part1.c)
target_compile_options(part1 PUBLIC -Wall -Wextra -Wshadow -Wpedantic -Wdouble-promotion -Wformat=2 -Wundef -Werror -Wcast-align=strict)
target_link_libraries(part1 PUBLIC m)

set(TEST_SUITES "expand_key_test" "encrypt_test" "part2" "part3")

  foreach(TEST_SUITE IN LISTS TEST_SUITES)
  add_executable(${TEST_SUITE} tests/src/${TEST_SUITE}.cpp src/hw2.c)
  target_compile_options(${TEST_SUITE} PUBLIC -g -Wall -Wextra -Wshadow -Wpedantic -Wdouble-promotion -Wformat=2 -Wundef -Werror -Wcast-align=strict)
  target_include_directories(${TEST_SUITE} PUBLIC include tests/include)
  target_link_libraries(${TEST_SUITE} PUBLIC gtest gtest_main pthread m)
  endforeach()

  add_executable(part_4_tests tests/src/expand_key_test.cpp tests/src/encrypt_test.cpp src/hw2.c)
  target_compile_options(part_4_tests PUBLIC -g -Wall -Wextra -Wshadow -Wpedantic -Wdouble-promotion -Wformat=2 -Wundef -Werror -Wcast-align=strict)
  target_include_directories(part_4_tests PUBLIC include tests/include)
  target_link_libraries(part_4_tests PUBLIC gtest gtest_main pthread m)
