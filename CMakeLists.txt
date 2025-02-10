cmake_minimum_required(VERSION 3.19)

if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()

option(TLS_CLIENT_BUILD_EXECUTABLE "Build executable" ON)
option(TLS_CLIENT_BUILD_STATIC_LIB "Build static library" OFF)
option(TLS_CLIENT_BUILD_SHARED_LIB "Build shared(dynamic) library" ON)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
	if(MSVC)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MT")
	else()
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
	endif()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(cpptls LANGUAGES CXX)
set(executable_srcs "examples/tls_client.cpp")

file(GLOB_RECURSE lib_srcs CONFIGURE_DEPENDS src/*.cpp include/*.h)
list(REMOVE_ITEM lib_srcs ${executable_srcs})
set(incl_dirs include)

find_package(OpenSSL REQUIRED)

set(ext_libs OpenSSL::SSL OpenSSL::Crypto)

if (TLS_CLIENT_BUILD_STATIC_LIB)
	add_library(tls STATIC ${lib_srcs})
	target_include_directories(tls PUBLIC ${incl_dirs})
	target_link_libraries(tls PRIVATE ${ext_libs})
	target_compile_definitions(tls PRIVATE LIBTLS_STATIC)
endif()

if (TLS_CLIENT_BUILD_SHARED_LIB)
	add_library(tls SHARED ${lib_srcs})
	target_include_directories(tls PUBLIC ${incl_dirs})
	target_link_libraries(tls PRIVATE ${ext_libs})
	target_compile_definitions(tls PRIVATE LIBTLS_EXPORTS)
endif()

if (TLS_CLIENT_BUILD_EXECUTABLE)
	if (TLS_CLIENT_BUILD_STATIC_LIB)  # prefer static
		set(LINKED_LIB tls)
	elseif(TLS_CLIENT_BUILD_SHARED_LIB)
		set(LINKED_LIB tls ${ext_libs})
	else()
		list(APPEND executable_srcs ${lib_srcs})
		set(LINKED_LIB ${ext_libs})
	endif()
	add_executable(TLS_client ${executable_srcs})
	target_include_directories(TLS_client PUBLIC ${incl_dirs})
	target_link_libraries(TLS_client PRIVATE ${LINKED_LIB})
	target_compile_definitions(TLS_client PRIVATE LIBTLS_STATIC)
endif()
