#include <iostream>
#include <aes.hpp>
#include <cstdlib>
#include <string>
#include <Hash.hpp>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <utils.hpp>
#include <fstream>
#include <array>

#define ENCRYPTION              0
#define DECRYPTION              1

#define DEFAULT_BUF_SIZE        (1000 * AES_BLOCK_SIZE)

// what kind of checksum shall be used
// SHA1 means less security but better performance
// use SHA256 for the reverse
#define PERFORMANCE     SHA1
#define SECURITY        SHA256
#define CHECKSUM        PERFORMANCE

// Macro used for hex dumping byte arrays
/*
#define HEX_DUMP(x, n)    for (int i = 0; i < (int) n; ++i) { \
                            int _x = x[i]; \
                            std::cout << std::hex << _x;} \
                            std::cout << std::dec << std::endl;
*/

static size_t _read(uint8_t *ptr, uint32_t num_bytes, FILE *f) {
    size_t b = 0;
    while (num_bytes && !feof(f)) {
        auto bytes_read = fread(ptr, 1, num_bytes, f);
        if (bytes_read < num_bytes && !feof(f) && ferror(f)) {
            throw std::runtime_error("unable to read from file");
        } else {
            num_bytes -= bytes_read;
            ptr += bytes_read;
            b += bytes_read;
        }
    }
    return b;
}

static size_t _write(const uint8_t *ptr, uint32_t num_bytes, FILE *f) {
    size_t b = 0;
    while (num_bytes) {
        auto bytes_written = fwrite(ptr, 1, num_bytes, f);
        if (bytes_written < num_bytes && ferror(f)) {
            throw std::runtime_error("unable to write to file");
        } else {
            num_bytes -= bytes_written;
            ptr += bytes_written;
            b += bytes_written;
        }
    }
    return b;
}

static bool iequals(const std::string &str1, const std::string &str2) {
    return str2.size() == str2.size() ? std::equal(str1.begin(), str1.end(), str2.begin(), [](char a, char b) -> bool {
        return std::tolower(a) == std::tolower(b);
    }) : false;
}

static uint64_t get_buffersize(const std::string &str) {
    if (!isdigit(str.back())) {
        auto str1 = str.substr(0, str.size() - 1);
        uint64_t mult;
        switch (str.back()) {
            case 'M': {
                mult = 1000000;
                break;
            } case 'K': {
                mult = 1000;
                break;
            }
            default: {
                return 0;
            }
        }
        return strto<uint64_t>(str1) * mult;
    } else {
        return strto<uint64_t>(str);
    }
}

static std::string read_password(const std::string &fname) {
    std::string contents;
    std::ifstream in(fname);
    if (!in) {
        std::cerr << "unable to read password from file" << std::endl;
        exit(EXIT_FAILURE);
    }
    in.seekg(0, std::ios::end);
    contents.resize(in.tellg());
    in.seekg(0, std::ios::beg);
    in.read((char *) contents.data(), contents.size());
    in.close();
    return contents;
}

static void encrypt_file(uint8_t *iv, FILE *in, FILE *out, uint8_t *key, uint32_t *exp_key, uint64_t bufsize) {
    // allocate buffer
    auto *buffer = (uint8_t*) malloc(bufsize);
    unsigned buffer_size = 0;

    // threefold hashing
    SHA256::hash(key, AES_KEY_SIZE, buffer);
    SHA256::hash(buffer, SHA256::HASH_SIZE, buffer);
    SHA256::hash(buffer, SHA256::HASH_SIZE, buffer);
    buffer_size = SHA256::HASH_SIZE;

    // hash of file content
    CHECKSUM::context ctx;
    CHECKSUM::init(ctx);

    // we attempt to fill up the buffer with as many bytes from input as possible
    // then the hash is updated and the full blocks of the input get encrypted
    // and written to output
    while (!feof(in)) {
        buffer_size += _read(buffer + buffer_size, (uint32_t) (bufsize - buffer_size), in);

        const unsigned num_blocks = buffer_size / AES_BLOCK_SIZE;
        CHECKSUM::update(ctx, buffer, num_blocks * AES_BLOCK_SIZE);
        aes_ctr_enc(buffer, buffer, exp_key, iv, num_blocks);

        _write(buffer, num_blocks * AES_BLOCK_SIZE, out);

        // reduce buffer size and copy leftover bytes (those that did not form a complete block)
        // to the beginning of the buffer
        buffer_size -= num_blocks * AES_BLOCK_SIZE;
        for (int i = 0; i < (int) buffer_size; ++i) {
            buffer[i] = buffer[(num_blocks * AES_BLOCK_SIZE) + i];
        }
    }

    // finish checksum to buffer
    CHECKSUM::update(ctx, buffer, buffer_size);
    CHECKSUM::final(ctx, buffer + buffer_size);
    buffer_size += SHA1::HASH_SIZE;

    // encrypt checksum and remaining bytes in buffer
    aes_ctr_enc(buffer, buffer, exp_key, iv, 3);
    _write(buffer, buffer_size, out);
}

static void decrypt_file(uint8_t *iv, FILE *in, FILE *out, uint8_t *key, uint32_t *exp_key, uint64_t bufsize) {
    // allocate buffer
    auto *buffer = (uint8_t*) malloc(bufsize);
    unsigned buffer_size = 0;

    if (_read(buffer, SHA256::HASH_SIZE, in) < SHA256::HASH_SIZE) {
        // unable to read hash of key from file due to not enough bytes available
        throw std::runtime_error("insufficient file size");
    }

    // check if the key hashes match
    uint8_t hash_of_key[AES_KEY_SIZE];
    SHA256::hash(key, AES_KEY_SIZE, hash_of_key);
    SHA256::hash(hash_of_key, AES_KEY_SIZE, hash_of_key);
    SHA256::hash(hash_of_key, AES_KEY_SIZE, hash_of_key);
    aes_ctr_dec(buffer, buffer, exp_key, iv, 2);
    if (memcmp(buffer, hash_of_key, AES_KEY_SIZE) != 0) {
        throw std::runtime_error("invalid password or compromised iv");
    }

    CHECKSUM::context ctx;
    CHECKSUM::init(ctx);
    CHECKSUM::update(ctx, hash_of_key, SHA256::HASH_SIZE);

    // empty buffer
    buffer_size = 0;

    while (!feof(in)) {
        buffer_size += _read(buffer + buffer_size, (uint32_t) (bufsize - buffer_size), in);

        // do not treat the last 20 bytes as normal file content as it is the SHA-1 checksum
        const unsigned num_blocks = (unsigned) (buffer_size - SHA1::HASH_SIZE) / AES_BLOCK_SIZE;
        aes_ctr_dec(buffer, buffer, exp_key, iv, num_blocks);
        CHECKSUM::update(ctx, buffer, num_blocks * AES_BLOCK_SIZE);

        _write(buffer, num_blocks * AES_BLOCK_SIZE, out);

        // reduce buffer size and copy leftover bytes (those that did not form a complete block and possible hash bytes)
        // to the beginning of the buffer
        buffer_size -= num_blocks * AES_BLOCK_SIZE;
        for (int i = 0; i < (int) buffer_size; ++i) {
            buffer[i] = buffer[(num_blocks * AES_BLOCK_SIZE) + i];
        }
    }

    aes_ctr_dec(buffer, buffer, exp_key, iv, (buffer_size + 15) / AES_BLOCK_SIZE);
    _write(buffer, (uint32_t) (buffer_size - SHA1::HASH_SIZE), out);

    // the last 20 bytes / 160 bit form the checksum
    uint8_t checksum[SHA1::HASH_SIZE];
    CHECKSUM::update(ctx, buffer, buffer_size - SHA1::HASH_SIZE);
    CHECKSUM::final(ctx, checksum);

    // check if checksum in file matches the checksum computed from the decrypted file
    // if they mismatch this maight be due to the file being corrupted or an error occurred
    if (memcmp(checksum, buffer + (buffer_size - SHA1::HASH_SIZE), SHA1::HASH_SIZE) != 0) {
        throw std::runtime_error("checksum mismatch, file may be corrupted");
    }
}

static void print_help() {
  std::cout << "acrypt [options...] <input file> <output file>" << std::endl;
  std::cout << "options:" << std::endl;
  std::cout << "if \'-\' is given as a filename, STDIN/STOUT is used " << std::endl;
  std::cout << "--encrypt, -e                encrpytion mode" << std::endl;
  std::cout << "--decrypt, -d                decryption mode" << std::endl;
  std::cout << "--buffersize=SIZE, -bs SIZE  set buffer size (e.g. -bs 4M)" << std::endl;
  std::cout << "--password=PASS, -p PASS     set password, if no password is specified then" << std::endl
            << "                             a prompt opens and it can be entered safely" << std::endl;
  std::cout << "--file=FILE, -f FILE         read plain text password from file" << std::endl;
  std::cout << "--hash=HASH, -h HASH         set the type of hash to be used for computing the checksum { none, sha1, sha256 }"<< std::endl
            << "                             default is --hash=sha1" << std::endl;
}

int main(int argc, const char *argv[]) {
    const std::vector<std::string> args(argv, argv + argc);
    if (argc >= 2 && args[1] == "--help") {
        print_help();
        return EXIT_SUCCESS;
    } else if (args.size() < 4) {
        std::cout << "Usage: " << argv[0] << " [options...] <input file> <output file>" << std::endl;
        return EXIT_FAILURE;
    }

    int mode = -1;
    std::string password;
    uint64_t buffer_size = DEFAULT_BUF_SIZE;
    auto hash = Hash::SHA256;

    for (size_t i = 1; i < args.size() - 2; ++i) {
        const auto &arg = args[i];
        if (starts_with(arg, "--encrypt") || starts_with(arg, "-e")) {
            mode = ENCRYPTION;
            continue;
        } else if (starts_with(arg, "--decrypt") || starts_with(arg, "-d")) {
            mode = DECRYPTION;
            continue;
        } else if (starts_with(arg, "--password=")) {
            auto tokens = split(arg, "=");
            if (tokens.size() == 2) {
                password = tokens[1];
            }
            continue;
        } else if (starts_with(arg, "-p")) {
            password = args[i + 1];
            i += 1;
            continue;
        } else if (starts_with(arg, "--buffersize=")) {
            auto tokens = split(arg, "=");
            if (tokens.size() == 2) {
                buffer_size = get_buffersize(tokens[1]);
            }
            continue;
        } else if (starts_with(arg, "-bs")) {
            buffer_size = get_buffersize(args[i + 1]);
            i += 1;
            continue;
        } else if (starts_with(arg, "--file=")) {
            auto tokens = split(arg, "=");
            if (tokens.size() == 2) {
                password = read_password(tokens[1]);
            }
            continue;
        } else if (starts_with(arg, "-f")) {
            password = read_password(args[i + 1]);
            i += 1;
            continue;
        } else if (starts_with(arg, "--hash=")) {
            auto tokens = split(arg, "=");
            if (tokens.size() == 2) {
                if (tokens[1] == "none") {
                    hash = Hash::NONE;
                } else if (tokens[1] == "sha1") {
                    hash = Hash::SHA1;
                } else if (tokens[1] == "sha256") {
                    hash = Hash::SHA256;
                } else {
                    std::cerr << "unrecognized hash type '" << tokens[1] << '\'' << std::endl;
                }
            }
            continue;
        } else if (starts_with(arg, "-h")) {
            if (args[i + 1] == "none") {
                hash = Hash::NONE;
            } else if (args[i + 1] == "sha1") {
                hash = Hash::SHA1;
            } else if (args[i + 1] == "sha256") {
                hash = Hash::SHA256;
            } else {
                std::cerr << "unrecognized hash type '" << args[i + 1] << '\'' << std::endl;
            }
            i += 1;
            continue;
        } else {
            std::cerr << "unrecognized argument '" << arg << '\'' << std::endl;
        }
    }

    if (mode < 0) {
        std::cerr << "mode not specified" << std::endl;
        return EXIT_FAILURE;
    }

    if (buffer_size < 256) {
        std::cerr << "invalid buffer size \'" << buffer_size << "\', must be at least 256 Bytes" << std::endl;
        return EXIT_FAILURE;
    }

    // rename filenames
    const std::string input_filename(argv[argc - 2]);
    const std::string output_filename(argv[argc - 1]);

    // get password
    if (password.empty()) {
        if (input_filename == "-") {
            std::cerr << "cannot read password when using STDIN as input" << std::endl;
            return EXIT_FAILURE;
        }
        // prompt the user
        const std::string passwd(getpass("enter password: "));
        const std::string confrm(getpass("confirm password: "));
        if (passwd.empty()) {
            std::cerr << "empty password is not allowed" << std::endl;
            exit(EXIT_FAILURE);
        }
        if (passwd != confrm) {
            std::cerr << "passwords mismatch" << std::endl;
            exit(EXIT_FAILURE);
        } else {
            password = passwd;
        }
    }

    // open input file, if filename=="-" use stdin
    FILE *in = input_filename != "-" ? fopen(input_filename.c_str(), "rb") : stdin;
    if (in == nullptr) {
        std::cerr << "unable to open input file" << std::endl;
        exit(EXIT_FAILURE);
    }

    // open output file, if filename=="-" use stdout
    FILE *out = output_filename != "-" ? fopen(output_filename.c_str(), "wb") : stdout;
    if (out == nullptr) {
        std::cerr << "unable to open output file" << std::endl;
        exit(EXIT_FAILURE);
    }

    // generate 16 Byte IV that is also used as a password salt
    std::array<uint8_t, AES_BLOCK_SIZE> iv = { 0 };
    if (mode == ENCRYPTION) {
        aes_generate_iv(iv.data());
        _write(iv.data(), iv.size(), out);
    } else {
        if (_read(iv.data(), iv.size(), in) < iv.size()) {
            std::cerr << "insufficient file size" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    // salted password aka password + salt must be at least 32 Bytes
    // if shorted, '#' is appended until 32 Bytes are reached
    std::vector<uint8_t> salted_password(std::max(password.size() + iv.size(), SHA256::HASH_SIZE));
    for (int i = 0; i < iv.size(); ++i) {
        salted_password[i] = iv[i];
    }
    for (int i = 0; i < password.size(); ++i) {
        salted_password[iv.size() + i] = UINT8_C(password[i]);
    }
    for (int i = password.size() + iv.size(); i < SHA256::HASH_SIZE; ++i) {
        salted_password[i] = UINT8_C('#');
    }

    // compute key from password
    std::array<uint8_t, AES_BLOCK_SIZE> key = { 0 };
    SHA256::hash(salted_password.data(), salted_password.size(), key.data());

    for (int i = 1; i < 8192; ++i) {
        SHA256::hash(key.data(), key.size(), key.data());
    }

    // expand key
    std::array<uint8_t, AES_EXP_KEY_SIZE> exp_key = { 0 };
    aes_ctr_expand_key(key.data(), (uint32_t*) exp_key.data());

    // do operation, catch exception
    try {
        if (mode == ENCRYPTION) {
            encrypt_file(iv.data(), in, out, key.data(), (uint32_t *) exp_key.data(), buffer_size);
        } else {
            decrypt_file(iv.data(), in, out, key.data(), (uint32_t *) exp_key.data(), buffer_size);
        }
    } catch (std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
    }

    // close files
    fclose(in);
    fclose(out);

    return EXIT_SUCCESS;
}