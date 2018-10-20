#ifndef __SHA256_HPP
#define __SHA256_HPP

#include <sha256.h>
#include <cstddef>

namespace SHA256 {

	typedef sha256_context context;

	inline void init(context &ctx) {
		sha256_starts(&ctx);
	}

	inline void update(context &ctx, const void *data, size_t len) {
		sha256_update(&ctx, (uint8*) data, (uint32) len);
	}

	inline void finish(context &ctx, void *digest) {
		sha256_finish(&ctx, (uint8*) digest);
	}

	inline void hash(const void *data, size_t len, void *digest) {
		SHA256::context ctx;
		SHA256::init(ctx);
		SHA256::update(ctx, data, len);
		SHA256::finish(ctx, digest);
	}

} // namespace SHA256

#endif // __SHA256_HPP
