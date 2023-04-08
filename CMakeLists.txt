cmake_minimum_required(VERSION 3.13...3.26 FATAL_ERROR)
project(demov VERSION 1.0.1 LANGUAGES CXX C)

set(SRC "asmhlp.cpp" "ctlelem.cpp" "ctlhlp.cpp" "demov.cpp" "dishlp.cpp" "elfhlp.cpp" "memhlp.cpp" "node.cpp" "tainthlp.cpp" "utils.cpp" "test.cpp")

add_executable(demov ${SRC})

target_link_libraries(demov PUBLIC "capstone" "keystone" "z3" "ssl" "crypto")
