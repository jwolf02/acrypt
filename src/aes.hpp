#ifndef __AES_HPP
#define __AES_HPP

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <ctime>

#if defined(__amd64__) || defined (__amd64)
#define __AMD64__
#endif

#define AES_BLOCK_SIZE    (16)
#define AES_KEY_SIZE      (32)
#define AES_EXP_KEY_SIZE  (240)

#define aes_ctr_enc aes_ctr_encdec
#define aes_ctr_dec aes_ctr_encdec

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
  srand((unsigned) clock());
  for (int i = 0; i < AES_BLOCK_SIZE; ++i)
    iv[i] = (uint8_t) rand();
}

inline void aes_ctr_expand_key(const uint8_t *key, uint32_t *exp_key) {
  #ifdef __AMD64__
  if (aes_has_cpu_support()) {
    aes_ctr_expand_key_aesni(key, exp_key);
  } else {
  #else
    // aes_ctr_expand_key_generic(key, exp_key);
  #endif

  #ifdef __AMD64__
  }
  #endif
}

inline void aes_ctr_encdec(const uint8_t *input, uint8_t *output, const uint32_t *exp_key, uint8_t *iv, uint64_t n) {
  #ifdef __AMD64__
  if (aes_has_cpu_support()) {
    aes_ctr_encdec_aesni(input, output, exp_key, iv, n);
  } else {
  #else
    // aes_ctr_encdec_generic(input, output, exp_key, iv, n);
  #endif

  #ifdef __AMD64__
  }
  #endif
}

#endif // __AES_HPP