#ifndef __AES_HPP
#define __AES_HPP

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <random>

#if defined(__amd64__) || defined (__amd64)
#define __AMD64__
#endif

#define AES_BLOCK_SIZE      (16)
#define AES_KEY_SIZE        (32)
#define AES_EXP_KEY_SIZE    (240)

// constants for convenience
#define aes_ctr_enc         aes_ctr_encdec
#define aes_ctr_dec         aes_ctr_encdec

void aes_ctr_expand_key_generic(const uint8_t *key, uint32_t *exp_key);
void aes_ctr_encdec_generic(const uint8_t *input, uint8_t *output, const uint32_t *exp_key, uint8_t *iv, uint64_t n);
void aes_ctr_expand_key_aesni(const uint8_t *key, uint32_t *exp_key);
void aes_ctr_encdec_aesni(const uint8_t *input, uint8_t *output, const uint32_t *exp_key, uint8_t *iv, uint64_t n);

#define cpuid(func,ax,bx,cx,dx)\
						__asm__ __volatile__ ("cpuid":\
						"=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

inline int aes_has_cpu_support() {
    #ifdef __AMD64__
    unsigned a, b, c, d;
    cpuid(1, a, b, c, d);
    return (c & 0x2000000);
    #else
    return 0;
    #endif
}

inline void aes_generate_iv(uint8_t *iv) {
    std::default_random_engine generator((unsigned long) clock());
    std::uniform_int_distribution<uint8_t> distribution(0, 255);

    for (auto it = iv; it != iv + AES_BLOCK_SIZE; ++it) {
        *it = distribution(generator);
    }
}

inline void aes_ctr_expand_key(const uint8_t *key, uint32_t *exp_key) {
    #ifdef __AMD64__
    if (aes_has_cpu_support())
        aes_ctr_expand_key_aesni(key, exp_key);
    else
    #endif
        aes_ctr_expand_key_generic(key, exp_key);
}

inline void aes_ctr_encdec(const uint8_t *input, uint8_t *output, const uint32_t *exp_key, uint8_t *iv, uint64_t n) {
    #ifdef __AMD64__
    if (aes_has_cpu_support())
        aes_ctr_encdec_aesni(input, output, exp_key, iv, n);
    else
    #endif
        aes_ctr_encdec_generic(input, output, exp_key, iv, n);
}

#endif // __AES_HPP