cmake_minimum_required(VERSION 3.9)
project(mersenne)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O3 -pthread -std=c++14 -maes -mavx -mpclmul -mbmi2 -fopenmp")
#set(CMAKE_CXX_STANDARD 11)

include_directories(/home/bush/Desktop/Avishay/NTL/ntl-10.5.0/include)

add_executable(mersenne
        Mersenne.cpp
        Mersenne.hpp
        Poly.cpp
        Poly.h
        main.cpp)

target_link_libraries(mersenne gmp gmpxx /home/bush/Desktop/Avishay/NTL/ntl-10.5.0/src/ntl.a)