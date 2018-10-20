#ifndef __AES_HPP
#define __AES_HPP

#include <cstdint>

#if defined(__amd64) || defined(__amd64__)
#define __AMD64__
#endif

#define cpuid(func,ax,bx,cx,dx) \
	__asm__ __volatile__ ("cpuid": \
	"=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

// This namespace contains all functions for AES-256-CBC
// For most cipher related functions a generic version for
// all systems is provided and a hardware accelerated version
// using Intel's AES-NI cpu support that only works on
// supporting amd64 systems. 
// The _generic or _aesni functions should not be called directly, 
// but rather the respective dispatcher without the suffix should 
// be used in order to use compatible function.
namespace AES {

// some useful constants
constexpr uint64_t BLOCK_SIZE = 16;
constexpr uint64_t EXP_KEY_SIZE = 240;
constexpr uint64_t KEY_SIZE = 32;

// modes for key schedule computation
constexpr int ENCRYPTION = 0;
constexpr int DECRYPTION = 1;

/*
 * Check if the amd64 system supports the AES-NI
 */
inline bool has_cpu_support() {
	#ifdef __AMD64__
	unsigned a, b, c, d;
	cpuid(1, a, b, c, d);
	return (c & 0x2000000) > 0;
	#else
	// non-amd64 systems don't support AES-NI
	return false;
	#endif
}

/* 
 * Generate a 16 byte random initialization vector
 */
void generate_iv(uint8_t *iv);

void expand_key_generic(int mode, const uint8_t *key, uint32_t *exp_key);

void expand_key_aesni(int mode, const uint8_t *key, uint32_t *exp_key);

/*
 * Dispatcher for the key expansion routines.
 * Computes the 15 16-byte round keys for the AES-256 cipher.
 * If mode is set to AES::ENCRYPTION an encryption key schedule
 * is computed, AES::DECRYPTION for mode computes an decryption
 * schedule.
 */
inline void expand_key(int mode, const uint8_t *key, uint32_t *exp_key) {
	#ifdef __AMD64__
	if (has_cpu_support()) {
		expand_key_aesni(mode, key, exp_key);
	} else {
	#endif
		expand_key_generic(mode, key, exp_key);
	#ifdef __AMD64__
	}
	#endif
}

void encrypt_generic(const uint8_t *input, uint8_t *output, const uint32_t *exp_key,
		uint8_t *iv, uint64_t length);

void encrypt_aesni(const uint8_t *input, uint8_t *output, const uint32_t *exp_key,
		uint8_t *iv, uint64_t length);

/*
 * Dispatcher for the encryption routine. Automatically switches to
 * hardware accelerated version if available.
 */
inline void encrypt(const uint8_t *input, uint8_t *output, const uint32_t *exp_key,
		uint8_t *iv, uint64_t length)
{
	#ifdef __AMD64__
	if (has_cpu_support()) {
		encrypt_aesni(input, output, exp_key, iv, length);
	} else {
	#endif
		encrypt_generic(input, output, exp_key, iv, length);
	#ifdef __AMD64__
	}
	#endif
}

void decrypt_generic(const uint8_t *input, uint8_t *output, const uint32_t *exp_key,
		uint8_t *iv, uint64_t length);

void decrypt_aesni(const uint8_t *input, uint8_t *output, const uint32_t *exp_key,
		uint8_t *iv, uint64_t length);

/*
 * Dispather for the decryption routine. Automatically swithces to
 * hardware accelerated version if available.
 */
inline void decrypt(const uint8_t *input, uint8_t *output, const uint32_t *exp_key,
		uint8_t *iv, uint64_t length)
{
	#ifdef __AMD64__
	if (has_cpu_support()) {
		decrypt_aesni(input, output, exp_key, iv, length);
	} else {
	#endif
		decrypt_generic(input, output, exp_key, iv, length);
	#ifdef __AMD64__
	}
	#endif
}

} // namespace AES

#endif // __AES_HPP
