# acrypt
AES-256 CTR based file encryption program.

## Usage
mkdir build  
cd build  
cmake ..  
make -j 4  
make install (optional)  
acrypt --encrypt password input.txt output.enc

## Features
acrypt uses hardware accelerated cipher routines (AES-NI) on machines that  
support them. Otherwise a generic (and one order of magnitude slower)   
fallback is used.  
On i5-6600U performance was: generic=170 MB/s, aesni=2.6 GB/s.  

## File format
acrypt uses a simple file format that uses no specific extension.  
  

