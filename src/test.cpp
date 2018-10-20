#include <iostream>
#include <cstdint>
#include <aes.hpp>
#include <memory.h>
#include <string>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <iomanip>

static const uint8_t nonce[AES::BLOCK_SIZE] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

static const uint8_t key[32] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 
	0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 
	0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

static const uint8_t input_block[AES::BLOCK_SIZE] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

static const uint8_t output_block[AES::BLOCK_SIZE] = {
	0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 
	0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28
};

static uint32_t exp_key[60];

template <typename cfunc_t>
void cipher_test(cfunc_t func) {
	uint8_t block[AES::BLOCK_SIZE];
	uint8_t lnonce[AES::BLOCK_SIZE];
	memcpy(lnonce, nonce, AES::BLOCK_SIZE);
	func(input_block, block, exp_key, lnonce, AES::BLOCK_SIZE);
	if (memcmp(block, output_block, AES::BLOCK_SIZE) == 0) {
		std::cout << "passed";
	} else {
		std::cout << "failed";
	}
	std::cout << std::endl;
}

#define ROUND(x)	(std::ceil((x) * 10) / 10) 

void print_result(double rate) {
	std::cout << std::setprecision(1) << std::fixed;
	if (rate >= double(1UL << 30)) {
		std::cout << ROUND(rate / double(1UL << 30)) << " GB/s";
	} else if (rate >= double(1UL << 20)) {
		std::cout << ROUND(rate / double(1UL << 20)) << " MB/s";
	} else if (rate >= double(1UL << 10)) {
		std::cout << ROUND(rate / double(1UL << 10)) << " KB/s";
	} else {
		std::cout << ROUND(rate) << " B/s";
	}
	std::cout << std::endl;
}

#define N	(1UL << 30)

template <typename cfunc_t>
void perf_test(cfunc_t func) {
	uint8_t lnonce[AES::BLOCK_SIZE];
	uint8_t *data = (uint8_t *) malloc(2 * N);
	clock_t begin, end;
	begin = clock();
	func(data, data + N, exp_key, lnonce, N);
	end = clock();
	double rate = double(N) / (double(end - begin) / CLOCKS_PER_SEC);
	print_result(rate);
	free(data);
}

int main(int argc, const char *argv[]) {
	std::cout << "AES-256 CTR Test Suite" << std::endl << std::endl;

	std::cout << "Cipher Test (AES-256 CTR)" << std::endl;
	/*	
	std::cout << "Generic: \t";
	AES::Key::expand_generic(key, exp_key);
	cipher_test(AES::CTR::encrypt_generic);
	
	std::cout << "AES-NI: \t";
	AES::Key::expand_aesni(key, exp_key);
	cipher_test(AES::CTR::encrypt_aesni);

	std::cout << std::endl;

	std::cout << "Performance (AES-256 CTR)" << std::endl;
	
	std::cout << "Generic: \t";
	perf_test(AES::CTR::encrypt_generic);

	std::cout << "AES-NI: \t";
	perf_test(AES::CTR::encrypt_aesni);
	*/
	return 0;
}
