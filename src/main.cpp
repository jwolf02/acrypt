#include <iostream>
#include <aes.hpp>
#include <fstream>
#include <cstdlib>
#include <string>
#include <cstdint>
#include <sha256.hpp>
#include <unistd.h>

// 4 MB
#define NUM_BYTES	(1 << 26)

typedef void (*cipher_t)(const uint8_t*, int, int);

void encrypt_file(const uint8_t *key, std::ifstream &in, std::ofstream &out) {
	uint8_t iv[AES::BLOCK_SIZE];
	uint8_t data_hash[32] = { 0 };
	uint64_t num_bytes = 0;
	uint8_t exp_key[AES::EXP_KEY_SIZE];

	AES::expand_key(key, exp_key);

	out.write((const char *) iv, sizeof(iv));

	uint8_t *buffer = (uint8_t *) malloc(NUM_BYTES);
	uint64_t buffer_size = 0;

	SHA256::context ctx;
	SHA256::init(ctx);

	while (!in.eof()) {
		in.read(((char *) buffer) + buffer_size, NUM_BYTES - buffer_size);
		uint64_t bytes_read = in.gcount();
		buffer_size += bytes_read;
		num_bytes += bytes_read;
		uint64_t num_blocks = buffer_size >> 4;
		SHA256::update(ctx, buffer, (num_blocks << 4));
		AES::encrypt(buffer, buffer, (const uint32_t *) exp_key,
				iv, num_blocks << 4);
		out.write((const char *) buffer, num_blocks << 4);

		// copy leftover bytes to begin of buffer
		for (int i = 0; i < buffer_size % 16; ++i) {
			buffer[i] = buffer[(num_blocks << 4) + i];
		}

		buffer_size %= 16;
	}
	
	SHA256::update(ctx, buffer, buffer_size);

	if (buffer_size) {
		uint8_t footer[64] = { 0 };
		for (int i = 0; i < buffer_size; ++i) {
			footer[i] = buffer[i];
		}

		((uint64_t *) footer)[3] = num_bytes;

		SHA256::finish(ctx, footer + 32);

		AES::encrypt(footer, footer, (const uint32_t *) exp_key,
				iv, 64);

		out.write((const char *) footer, 64);
	} else {
		uint8_t footer[48] = { 0 };

		((uint64_t *) footer)[1] = num_bytes;

		SHA256::finish(ctx, footer + 16);

		AES::encrypt(footer, footer, (const uint32_t *) exp_key,
				iv, 48);

		out.write((const char *) footer, 48);
	}
}

void decrypt_file(const uint8_t *key, std::ifstream &in, std::ofstream &out) {
	
}

void derive_key(const std::string &password, uint8_t *key) {
	SHA256::hash(password.data(), password.size(), key);

	for (int i = 1; i < 8192; ++i) {
		SHA256::hash(key, 32, key);
	}
}

int main(int argc, const char *argv[]) {

	// check arguments
	if (argc < 4) {
		std::cout << "Usage: " << argv[0] << " {-e | -d} [password] <input file> <output file>"
			<< std::endl;
		exit(EXIT_SUCCESS);
	}

	// Get mode from first argument
	const std::string mode(argv[1]);
	cipher_t cipher = nullptr;
	if (mode == "-e") {
		cipher = encrypt_file;
	} else if (mode == "-d") {
		cipher = decrypt_file;
	} else {
		std::cerr << "Unrecognized mode '" << argv[1] << "'" << std::endl;
		return EXIT_FAILURE;
	}

	// increment value in case password is given as argument
	const int inc = argc >= 5 ? 1 : 0;

	// get password as argument or query user
	std::string password;
	if (argc < 5) {
		password = getpass("Enter password: ");
		std::string validation(getpass("Repeat password: "));
		if (password != validation) {
			std::cerr << "Password do not match!" << std::endl;
			exit(1);
		}
	} else {
		password = argv[2];
	}
	
	std::ifstream in_file(argv[2 + inc], 
			std::ios::in | std::ios::binary);
	std::ofstream out_file(argv[3 + inc], 
			std::ios::out | std::ios::trunc | std::ios::binary);

	if (!in_file) {
		std::cerr << "Could not open input file '" << argv[2 + inc] << "'\n";
		exit(1);
	}

	if (!out_file) {
		std::cerr << "Could not open output file '" << argv[3 + inc] << "'\n";
		exit(1);
	}

	uint8_t key[AES::KEY_SIZE] = { 0 };
	derive_key(password, key);

	cipher(key, in_file, out_file);

	in_file.close();
	out_file.close();

	return EXIT_SUCCESS;
}

