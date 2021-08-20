cmake_minimum_required(VERSION 3.12)
project(Final VERSION 1.0)
add_executable(main "main.cpp") 



find_package(SEAL)
target_link_libraries(main SEAL::seal)

