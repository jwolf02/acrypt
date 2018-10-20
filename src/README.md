## acrpyt

# File Format

All file content is encrypted by a key derived from the password.

Byte offset
0			First 8 byte of IV (Random)
8			Lowest 8 bytes from the hash of the Key
16			File content
n			Hash of file content

Memory footprint of  encrypted file is n + 48 bytes

