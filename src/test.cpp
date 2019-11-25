#include <iostream>
#include <aes.hpp>
#include <cstring>
#include <iomanip>
#include <hash.hpp>

// 1 GB / AES_BLOCK_SIZE
#define N   (62500000)

#define IF_HARDWARE_SUPPORT if (aes_has_cpu_support()) {

#define ENDIF_HARDWARE_SUPPORT }

// Macro used for hey dumping byte arrays
/*
#define HEX_DUMP(x, n)    for (int i = 0; i < n; ++i) { \
                            int _x = x[i]; \
                            std::cout << std::hex << _x;} \
                            std::cout << std::dec << std::endl;
*/

const uint8_t key[AES_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

const uint8_t counter[AES_BLOCK_SIZE] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

const uint8_t plaintext[AES_BLOCK_SIZE] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

const uint8_t ciphertext[AES_BLOCK_SIZE] = {
        0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
        0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28
};

const uint8_t sha1_test[SHA1::HASH_SIZE] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d
};

const uint8_t sha256_test[SHA256::HASH_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

// print bytes per second
static void get_performance(clock_t diff) {
    double bytes_per_sec = (double(N) * AES_BLOCK_SIZE) / (double(diff) / double(CLOCKS_PER_SEC));
    std::cout << std::fixed << std::setprecision(2);
    if (bytes_per_sec >= 1000000000.0) {
        std::cout << (bytes_per_sec / 1000000000.0) << " GB/s" << std::endl;
    } else if (bytes_per_sec >= 1000000.0) {
        std::cout << (bytes_per_sec / 1000000.0) << " MB/s" << std::endl;
    } else if (bytes_per_sec >= 1000.0) {
        std::cout << (bytes_per_sec / 1000.0) << " kB/s" << std::endl;
    } else {
        std::cout << bytes_per_sec << " B/s" << std::endl;
    }
}

// test performance
template <typename func_t>
static void test(func_t func) {
    clock_t begin = clock();
    func();
    clock_t end = clock();
    get_performance(end - begin);
}

uint8_t exp_key[AES_EXP_KEY_SIZE];
uint8_t tmp[AES_BLOCK_SIZE];
uint8_t iv[AES_BLOCK_SIZE];
uint8_t digest[SHA256::HASH_SIZE];

int main(int argc, const char *argv[]) {
    // allocate 1GB of memory
    auto *buffer = (uint8_t*) malloc(N * AES_BLOCK_SIZE);

    std::cout << "acrypt AES-256 CTR / SHA-1 / SHA-256 Test Suite" << std::endl << std::endl;

    std::cout << "hardware support: ";
    if (aes_has_cpu_support())
        std::cout << "enabled";
    else
        std::cout << "disabled";
    std::cout << std::endl << std::endl;

    std::cout << "Cipher test" << std::endl;

    std::cout << "Generic: \t" << std::flush;
    aes_ctr_expand_key_generic(key, (uint32_t*) exp_key);
    memcpy(iv, counter, AES_BLOCK_SIZE);
    aes_ctr_encdec_generic(plaintext, tmp, (uint32_t*) exp_key, iv, 1);
    if (memcmp(tmp, ciphertext, AES_BLOCK_SIZE) == 0)
        std::cout << "successful" << std::endl;
    else
        std::cout << "failed" << std::endl;

    IF_HARDWARE_SUPPORT

        std::cout << "AES-NI: \t" << std::flush;
        aes_ctr_expand_key_aesni(key, (uint32_t*) exp_key);
        memcpy(iv, counter, AES_BLOCK_SIZE);
        aes_ctr_encdec_aesni(plaintext, tmp, (uint32_t*) exp_key, iv, 1);
        if (memcmp(tmp, ciphertext, AES_BLOCK_SIZE) == 0)
            std::cout << "successful" << std::endl;
        else
            std::cout << "failed" << std::endl;

    ENDIF_HARDWARE_SUPPORT

    std::cout << std::endl << "Hash test" << std::endl;

    std::cout << "SHA-1:   \t" << std::flush;
    SHA1::hash("abc", 3, digest);
    if (memcmp(digest, sha1_test, SHA1::HASH_SIZE) == 0)
        std::cout << "successful" << std::endl;
    else
        std::cout << "failed" << std::endl;

    std::cout << "SHA-256: \t" << std::flush;
    SHA256::hash("abc", 3, digest);
    if (memcmp(digest, sha256_test, SHA256::HASH_SIZE) == 0)
        std::cout << "successful" << std::endl;
    else
        std::cout << "failed" << std::endl;

    std::cout << std::endl << "Performance test" << std::endl;

    std::cout << "Generic: \t" << std::flush;
    aes_ctr_expand_key_generic(key, (uint32_t*) exp_key);
    test([&](){ aes_ctr_encdec_generic(buffer, buffer, (uint32_t*) exp_key, iv, N); });

    IF_HARDWARE_SUPPORT

        std::cout << "AES-NI: \t" << std::flush;
        aes_ctr_expand_key_aesni(key, (uint32_t*) exp_key);
        test([&](){ aes_ctr_encdec_aesni(buffer, buffer, (uint32_t*) exp_key, iv, N); });

    ENDIF_HARDWARE_SUPPORT

    std::cout << "SHA-1:   \t" << std::flush;
    test([&](){ SHA1::hash(buffer, N * AES_BLOCK_SIZE, digest); });

    std::cout << "SHA-256: \t" << std::flush;
    test([&](){ SHA256::hash(buffer, N * AES_BLOCK_SIZE, digest); });

    free(buffer);

    return 0;
}
