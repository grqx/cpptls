cmake_minimum_required(VERSION 3.19)

if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()

option(LIBCPPTLS_BUILD_STATIC "Build static library" OFF)
option(LIBCPPTLS_BUILD_SHARED "Build shared(dynamic) library" ON)
option(LIBCPPTLS_BUILD_EXAMPLES "Build examples" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(cpptls LANGUAGES CXX)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
	if (MSVC)
		# message(STATUS "Setting MSVC Linker Arguments")
		# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MT")
	elseif(CMAKE_COMPILER_IS_GNUCXX)
		message(STATUS "Setting Linker Arguments For ${CMAKE_CXX_COMPILER_ID}")
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
	endif()
endif()

file(GLOB_RECURSE lib_srcs CONFIGURE_DEPENDS src/*.cpp include/*.h)
set(incl_dirs include)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
set(ext_libs OpenSSL::SSL OpenSSL::Crypto)

if (LIBCPPTLS_BUILD_STATIC)
	add_library(cpptls STATIC ${lib_srcs})
	target_include_directories(cpptls PUBLIC ${incl_dirs})
	target_link_libraries(cpptls PRIVATE ${ext_libs})
	target_compile_definitions(cpptls PRIVATE LIBCPPTLS_STATIC)
endif()

if (LIBCPPTLS_BUILD_SHARED)
	add_library(cpptlsDyn SHARED ${lib_srcs})
	target_include_directories(cpptlsDyn PUBLIC ${incl_dirs})
	if (LIBCPPTLS_BUILD_STATIC)  # prefer static ver
		target_link_libraries(cpptlsDyn PRIVATE cpptls)
	else()
		target_link_libraries(cpptlsDyn PRIVATE ${ext_libs})
	endif()
	target_compile_definitions(cpptlsDyn PRIVATE LIBTLS_EXPORTS)
endif()

if (LIBCPPTLS_BUILD_EXAMPLES)
	add_subdirectory(examples)
endif()

