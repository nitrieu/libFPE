
#project(libFPE)


#############################################
#                 Link Boost                #
#############################################

find_library(
  Boost_LIBRARIES 
  NAMES Boost  
  HINTS "${BOOST_ROOT}/boost")

set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost COMPONENTS system thread)

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
#              Build libFPE                #
#############################################

file(GLOB_RECURSE SRCS *.cpp)
 

add_library(libFPE ${SRCS})


target_include_directories(libFPE PUBLIC ${Boost_INCLUDE_DIR}) 
target_include_directories(libFPE PUBLIC ${CMAKE_SOURCE_DIR}/libFPE) 

target_link_libraries(libFPE cryptoTools ${MIRACL_LIB}  ${Boost_LIBRARIES})
