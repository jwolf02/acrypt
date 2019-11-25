#ifndef __HASH_HPP
#define __HASH_HPP

#include <sha256.hpp>
#include <sha1.hpp>
#include <cstddef>
#include <cstdint>

namespace None {

    constexpr uint64_t HASH_SIZE = 0;

    typedef struct{} context;

    inline void init(context &ctx) {
        return;
    }

    inline void update(context &ctx, const void *data, size_t len) {
        return;
    }

    inline void final(context &ctx, void *digest) {
        return;
    }

    inline void hash(const void *data, size_t len, void *digest) {
        return;
    }

} // namespace None

namespace SHA256 {

	constexpr uint64_t HASH_SIZE = 32;

	typedef sha256_context context;

	inline void init(context &ctx) {
		sha256_starts(&ctx);
	}

	inline void update(context &ctx, const void *data, size_t len) {
		sha256_update(&ctx, (const uint8*) data, (uint32) len);
	}

	inline void final(context &ctx, void *digest) {
		sha256_finish(&ctx, (uint8*) digest);
	}

	inline void hash(const void *data, size_t len, void *digest) {
		context ctx;
		init(ctx);
		update(ctx, data, len);
		final(ctx, digest);
	}

} // namespace SHA256

namespace SHA1 {

  constexpr uint64_t HASH_SIZE = 20;

  typedef SHA1_CTX context;

  inline void init(context &ctx) {
    SHA1Init(&ctx);
  }

  inline void update(context &ctx, const void *data, size_t len) {
    SHA1Update(&ctx, (const unsigned char *) data, (uint32_t) len);
  }

  inline void final(context &ctx, void *digest) {
    SHA1Final((unsigned char*) digest, &ctx);
  }

  inline void hash(const void *data, size_t len, void *digest) {
    context ctx;
    init(ctx);
    update(ctx, data, len);
    final(ctx, digest);
  }

} // namespace SHA1

#endif // __HASH_HPP
