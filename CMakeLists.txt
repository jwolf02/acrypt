cmake_minimum_required(VERSION 3.6)

project(crypt LANGUAGES C CXX)

set(CMAKE_CXX_STANDART	11)

set(CXX_FLAGS	"-Wall -O3 -pedantic -march=native -mtune=native -maes")

set(CMAKE_CXX_FLAGS	${CMAKE_CXX_FLAGS} ${CXX_FLAGS})

# aes library files
set(AES_SOURCES		src/aes.cpp)

set(AES_HEADERS		src/aes.hpp)

# crypt executable files
set(CRYPT_SOURCES	${AES_SOURCES}
			src/acrypt.cpp
			src/sha256.c)

set(CRYPT_HEADERS	${AES_HEADERS}
			src/sha256.h
			src/sha256.hpp)

# test suite files
set(TEST_SOURCES	${AES_SOURCES}
			src/test.cpp)

set(TEST_HEADERS	${AES_HEADERS})

# build the crypt executable
add_executable(acrypt ${CRYPT_SOURCES} ${CRYPT_HEADERS})
target_include_directories(acrypt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# built the test suite
add_executable(test_suite ${TEST_SOURCES} ${TEST_HEADERS})
target_include_directories(test_suite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# run test suite
add_custom_command(TARGET test_suite POST_BUILD COMMAND "./test_suite")

# install crypt
install(TARGETS acrypt DESTINATION /usr/bin)

