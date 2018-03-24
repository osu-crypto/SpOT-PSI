cmake_minimum_required(VERSION 3.5)
project(PSI)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O3 -pthread -std=c++14 -maes -mavx -mpclmul -mbmi2 -fopenmp")

INCLUDE_DIRECTORIES( $ENV{HOME} $ENV{HOME}/ntl-10.5.0/include $ENV{HOME}/libscapi/install/include
        $ENV{HOME}/libscapi/lib/OTExtensionBristol)

set(SOURCE_FILES main.cpp Party.h Party.cpp PartyR.cpp PartyS.cpp PartyS.h PartyR.h Defines.h Poly.cpp Poly.h
          zp.cpp zp.h)


link_directories($ENV{HOME}/libscapi/install/lib)


add_executable(PSI ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(PSI
        $ENV{HOME}/libscapi/libscapi.a gmp gmpxx
        libjsoncpp.a OTExtensionBristol libsimpleot.a
        $ENV{HOME}/ntl-10.5.0/src/ntl.a
        boost_system boost_thread pthread crypto dl ssl z rt)