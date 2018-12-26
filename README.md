# acrypt
AES-256 CTR based file encryption program.

## Usage
mkdir build  
cd build  
cmake ..  
make -j 2  
./test_suite  
make install (optional)  
acrypt -e password input.txt output.enc

## Features
acrypt uses hardware accelerated cipher routines (AES-NI) on machines that  
support them. Otherwise a generic (and one order of magnitude slower)   
fallback is used.  
On i5-6600U performance was: generic=170 MB/s, aesni=3.1 GB/s.  
It also uses SHA-1 and SHA-256 with performances of >500 MB/s and >100 MB/s.  

## File format
acrypt uses a simple file format that uses no specific extension.  
  

