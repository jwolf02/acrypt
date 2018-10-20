#!/bin/bash

clang++ -DTEST -Wall -O3 -std=c++11 -mtune=native -march=native -o ../bin/test_aes aes256.cpp -I../include
clang++ -DTEST -Wall -O3 -std=c++11 -mtune=native -march=native -o ../bin/test_sha sha256.cpp -I../include

cd ../bin

./test_aes

echo 

./test_sha

cd ../src
