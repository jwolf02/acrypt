cmake_minimum_required(VERSION 3.6)
project(acrypt LANGUAGES 	CXX)

set(CMAKE_CXX_STANDARD		11)

set(CMAKE_CXX_FLAGS	"${CMAKE_CXX_FLAGS} -Wall -O3 -pedantic -march=native -mtune=native -maes")

# library sources
set(LIB_SOURCES 	src/sha1.hpp
					src/sha1.cpp
					src/sha256.hpp
					src/sha256.cpp
        src/Hash.hpp
					src/aes.hpp
					src/aes.cpp)

# crypt executable files
set(ACRYPT_SOURCES	${LIB_SOURCES}
					src/main.cpp src/utils.hpp)

# test suite files
set(TEST_SOURCES	${LIB_SOURCES}
					src/test.cpp)

# build the crypt executable
add_executable(acrypt ${ACRYPT_SOURCES})
target_include_directories(acrypt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# built the test suite
add_executable(test_suite ${TEST_SOURCES})
target_include_directories(test_suite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# install acrypt
install(TARGETS acrypt DESTINATION /usr/bin)
