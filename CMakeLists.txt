cmake_minimum_required (VERSION 3.5)

if(WIN32)
	set(HOST Win32)
	set(PLATFORM x86)
	set(LIB lib)
	set(PROJECT "raop_play")
else()
	if(NOT HOST OR NOT PLATFORM)
		if(CMAKE_C_COMPILER)
			set(C_COMPILER ${CMAKE_C_COMPILER})
			message(STATUS "using CMAKE_C_COMPILER ${CMAKE_C_COMPILER}")
		else()
			execute_process(COMMAND bash "-c" "readlink -f `which cc`" OUTPUT_VARIABLE C_COMPILER)
			cmake_path(GET C_COMPILER FILENAME C_COMPILER)
			message(STATUS "guessing compiler ${C_COMPILER}")
		endif()

		string(REGEX MATCHALL "([^-]+)" CC_SPLIT ${C_COMPILER})

		list(GET CC_SPLIT 0 PLATFORM)
		list(LENGTH CC_SPLIT C_TUPLE_SIZE)

		if(C_TUPLE_SIZE EQUAL 5)
			list(GET CC_SPLIT 1 HOST)
		else()
			list(GET CC_SPLIT 2 HOST)
		endif()
	endif()

	set(LIB a)
	set(PROJECT "raop_play-${HOST}-${PLATFORM}")
endif()

if(NOT HOST OR NOT PLATFORM)
	message(STATUS "cannot define HOST (${HOST}) and/or PLATFORM ${PLATFORM}")
	return()
endif()

set(BASE ${CMAKE_CURRENT_SOURCE_DIR})
project(${PROJECT})

message(STATUS "Base directory is ${BASE}")
message(STATUS "Using CC ${CMAKE_C_COMPILER} and ${CMAKE_CXX_COMPILER}")
message(STATUS "Building for ${HOST}-${PLATFORM} with cmake's definition ${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")

# Configurable options
set(CMAKE_CXX_STANDARD 17)

if(MSVC)
	add_compile_definitions(NOMINMAX _WINSOCK_DEPRECATED_NO_WARNINGS _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_DEPRECATE)
	add_definitions(/wd4068 /wd4244 /wd4018 /wd4101 /wd4102 /wd4142 /wd4996 /wd4090)
else()
	add_compile_options(-O2 -fdata-sections -ffunction-sections)
    # who knows why it must be there and not in add_compile_options... well, that's CMake
    # oh, and setting "POSITION_INDEPENDENT_CODE" property does not wrok, of course
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -no-pie")
endif()

# Main target sources
file(GLOB SOURCES src/*.cpp src/*.c ${BASE}/crosstools/src/*.c)
list(APPEND SOURCES ${BASE}/dmap-parser/dmap_parser.c)
list(APPEND EXTRA_INCLUDES src)
add_executable(${PROJECT} ${SOURCES})

# Other includes
list(APPEND EXTRA_INCLUDES ${BASE}/crosstools/src ${BASE}/dmap-parser)

# openSSL manually
target_include_directories(${PROJECT} PRIVATE ${BASE}/libopenssl/targets/${HOST}/${PLATFORM}/include)
target_link_libraries(${PROJECT} PRIVATE ${BASE}/libopenssl/targets/${HOST}/${PLATFORM}/libopenssl.${LIB})

# codecs with cmake
find_package(libcodecs REQUIRED CONFIG PATHS ${BASE}/libcodecs)
get_target_property(_INFO libcodecs::codecs INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(${PROJECT} PRIVATE "${_INFO}")
get_target_property(_INFO libcodecs::codecs IMPORTED_LOCATION_RELEASE)
target_link_libraries(${PROJECT} PRIVATE ${_INFO})

# mDNS manually
target_include_directories(${PROJECT} PRIVATE ${BASE}/libmdns/targets/include/mdnssvc)
target_include_directories(${PROJECT} PRIVATE ${BASE}/libmdns/targets/include/mdnssd)
target_link_libraries(${PROJECT} PRIVATE ${BASE}/libmdns/targets/${HOST}/${PLATFORM}/libmdns.${LIB})

# pthreads manually
if(MSVC)
    target_include_directories(${PROJECT} PRIVATE ${BASE}/common/libpthreads4w/targets/${HOST}/${PLATFORM}/include)
    target_link_libraries(${PROJECT} PRIVATE ${BASE}/common/libpthreads4w/targets/${HOST}/${PLATFORM}/libpthreadVC3.lib)
endif()

# Configure the target
if(NOT MSVC)
    target_link_libraries(${PROJECT} PUBLIC stdc++ m pthread dl)
	if(NOT APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "SunOS")
		#target_link_options(${PROJECT} PUBLIC -static)
	endif()
    if(CMAKE_SYSTEM_NAME STREQUAL Linux AND CMAKE_SYSTEM_PROCESSOR STREQUAL x86_64)
		set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -lmvec")
	endif()
	if(CMAKE_SYSTEM_NAME STREQUAL SunOS)
		set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE} -lssp")
	endif()
endif()

target_compile_definitions(${PROJECT} PRIVATE -DNDEBUG -D_GNU_SOURCE)
target_include_directories(${PROJECT} PRIVATE "." ${EXTRA_INCLUDES})