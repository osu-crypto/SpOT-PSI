
#project(libPSI)


##############################################
##                 Link NTL                  #
##############################################
set(NTL_Lib_Dirs "${NTL_Dirs}src/")
set(NTL_Include_Dirs "${NTL_Dirs}include/")

# default location for NTL
#set(NTL_LIB "${NTL_Lib_Dirs}nnnnlibntl.a")


#if(NOT EXISTS "${NTL_LIB}")
  # we failed to find it, try using find_library
  find_library(
    NTL_LIB 
    NAMES ntl libntl.a  
    PATHS "${NTL_Lib_Dirs}")
  
  # if we still cant fint it, throw an error
  if(NOT NTL_LIB) 
	if(EXISTS "${NTL_Lib_Dirs}libntl.a")
		set(NTL_LIB "${NTL_Lib_Dirs}libntl.a")
	else()
	   Message(${NTL_LIB})
		message(FATAL_ERROR "Failed to find NTL at ${NTL_Lib_Dirs} or at system locations." )
	endif()
  endif()
#endif()


message(STATUS "NTL  ${NTL_LIB}")
message(STATUS "NTL  ${NTL_Include_Dirs}")
message(STATUS "NTL  ${NTL_Lib_Dirs}")
##############################################
##                 Link GMP                  #
##############################################
set(GMP_Lib_Dirs "${GMP_Dirs}lib/")
set(GMP_Include_Dirs "${GMP_Dirs}include/")
  find_library(
    GMP_LIB 
    NAMES gmp libgmp.a  
    PATHS "${GMP_Lib_Dirs}")
  
  # if we still cant fint it, throw an error
  if(NOT GMP_LIB) 
	if(EXISTS "${GMP_Lib_Dirs}libgmp.a")
		set(GMP_LIB "${GMP_Lib_Dirs}libgmp.a")
	else()
	   Message(${GMP_LIB})
		message(FATAL_ERROR "Failed to find GMP at ${GMP_Lib_Dirs} or at system locations." )
	endif()
  endif()
#endif()


message(STATUS "GMP  ${GMP_LIB}")
message(STATUS "GMP  ${GMP_Include_Dirs}")
message(STATUS "GMP  ${GMP_Lib_Dirs}")

##############################################
##                 Link GF2X                  #
##############################################
set(GF2X_Lib_Dirs "${GF2X_Dirs}lib/")
set(GF2X_Include_Dirs "${GF2X_Dirs}include/")
  find_library(
    GF2X_LIB 
    names gf2x libgf2x.a  
    paths "${GF2X_Lib_Dirs}")
  
  # if we still cant fint it, throw an error
  if(NOT GF2X_LIB) 
	if(EXISTS "${GF2X_Lib_Dirs}libgf2x.a")
		set(GF2X_LIB "${GF2X_Lib_Dirs}libgf2x.a")
	else()
	   message(${GF2X_LIB})
		message(fatal_error "failed to find gf2x at ${GF2X_Lib_Dirs} or at system locations." )
	endif()
  endif()
#endif()

message(status "gf2x  ${GF2X_LIB}")
message(status "gf2x ${GF2X_Include_Dirs}")
message(status "gf2x ${GF2X_Lib_Dirs}")


#############################################
#                 Link Boost                #
#############################################


set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost  COMPONENTS system thread)

if(Boost_FOUND)
  message( "Found Boost at ${Boost_LIBRARIES}")
else()
   message(FATAL_ERROR "Failed to find boost at " ${Boost_Lib_Dirs} " Need system thread")
endif()

 
#############################################
#                 Link Miracl               #
#############################################
find_library(
  MIRACL_LIB 
  NAMES miracl  
  HINTS "${Miracl_Dirs}/miracl/source/")
  
# if we cant fint it, throw an error
if(NOT MIRACL_LIB)
  Message(${MIRACL_LIB})
  message(FATAL_ERROR "Failed to find miracl at " ${Miracl_Dirs})
else()
  message("Miracl at  ${MIRACL_LIB}")
endif()




#############################################
#                 Link libOTe               #
#############################################


find_library(
    libOTe_LIB
    NAMES libOTe
    HINTS "${libOTe_Dirs}/lib/")
	
find_library(
    cryptoTools_LIB
    NAMES cryptoTools
    HINTS "${libOTe_Dirs}/lib/")

	
#############################################
#              Build libPSI                #
#############################################

file(GLOB_RECURSE SRCS *.cpp)
 

add_library(libPSI ${SRCS})


target_include_directories(libPSI PUBLIC ${Boost_INCLUDE_DIR}) 
target_include_directories(libPSI PUBLIC ${NTL_Include_Dirs}) 
target_include_directories(libPSI PUBLIC ${GMP_Include_Dirs})
target_include_directories(libPSI PUBLIC ${GF2X_Include_Dirs})
target_include_directories(libPSI PUBLIC ${CMAKE_SOURCE_DIR}/libPSI) 
target_include_directories(libPSI PUBLIC ${CMAKE_SOURCE_DIR}/libPSI) 

target_link_libraries(libPSI ${libOTe_LIB}  ${cryptoTools_LIB} ${MIRACL_LIB}  ${Boost_LIBRARIES} ${NTL_LIB} ${GMP_LIB} ${GF2X_LIB} )
