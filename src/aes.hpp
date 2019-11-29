#ifndef __AES_HPP
#define __AES_HPP

#include <cstdint>
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

// basic cipher routines
extern void aes_ctr_expand_key_generic(const uint8_t *key, uint32_t *exp_key);
extern void aes_ctr_encdec_generic(const uint8_t *input, uint8_t *output, const uint32_t *exp_key, uint8_t *iv, uint64_t n);
extern void aes_ctr_expand_key_aesni(const uint8_t *key, uint32_t *exp_key);
extern void aes_ctr_encdec_aesni(const uint8_t *input, uint8_t *output, const uint32_t *exp_key, uint8_t *iv, uint64_t n);

#define cpuid(func,ax,bx,cx,dx)\
						__asm__ __volatile__ ("cpuid":\
						"=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

/***
 * check if the amd64 cpu supports AES-NI
 * @return
 */
inline bool aes_has_cpu_support() {
    #ifdef __AMD64__
    unsigned a, b, c, d;
    cpuid(1, a, b, c, d);
    return (bool) ((c & 0x2000000) != 0);
    #else
    return false;
    #endif
}

/***
 * compute a 128 bit random iv
 * @param iv
 */
inline void aes_generate_iv(uint8_t *iv) {
    std::random_device rd;
    std::default_random_engine generator(rd);
    std::uniform_int_distribution<uint8_t> distribution(std::numeric_limits<uint8_t>::min(), std::numeric_limits<uint8_t>::max());

    for (auto it = iv; it != iv + AES_BLOCK_SIZE; ++it) {
        *it = distribution(generator);
    }
}

/***
 * compute the expanded key from the 256 bit key
 * @param key
 * @param exp_key
 */
inline void aes_ctr_expand_key(const uint8_t *key, uint32_t *exp_key) {
    static const bool hw_support = aes_has_cpu_support();
    if (hw_support) {
        aes_ctr_expand_key_aesni(key, exp_key);
    } else {
        aes_ctr_expand_key_generic(key, exp_key);
    }
}

/***
 * run enc/dec routine on data
 * @param input input data
 * @param output output buffer
 * @param exp_key
 * @param iv
 * @param n number of blocks
 */
inline void aes_ctr_encdec(const uint8_t *input, uint8_t *output, const uint32_t *exp_key, uint8_t *iv, uint64_t n) {
    static const bool hw_support = aes_has_cpu_support();
    if (hw_support) {
        aes_ctr_encdec_aesni(input, output, exp_key, iv, n);
    } else {
        aes_ctr_encdec_generic(input, output, exp_key, iv, n);
    }
}

#endif // __AES_HPP
