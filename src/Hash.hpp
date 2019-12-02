#ifndef __HASH_HPP
#define __HASH_HPP

#include <sha256.hpp>
#include <sha1.hpp>
#include <cstddef>
#include <cstdint>

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

/***
 * Wrapper class that can dynamically compute hashes from different digests
 */
class Hash {
public:

    enum hash_t {
        NONE = 0,
        SHA1 = 1,
        SHA256 = 2
    };

    explicit Hash(hash_t hash) : _hash(hash) {}

    uint64_t hash_size() const {
        switch (_hash) {
            case SHA256: {
                return SHA256::HASH_SIZE;
            } case SHA1: {
                return SHA1::HASH_SIZE;
            }
            default:
                return 0;
        }
    }

    hash_t hash() const {
        return _hash;
    }

    void init() {
        switch (_hash) {
            case SHA256: {
                SHA256::init(_sha256_ctx);
                break;
            } case SHA1: {
                SHA1::init(_sha1_ctx);
                break;
            }
            default:
                break;
        }
    }

    void update(const void *data, size_t len) {
        switch (_hash) {
            case SHA256: {
                SHA256::update(_sha256_ctx, data, len);
                break;
            } case SHA1: {
                SHA1::update(_sha1_ctx, data, len);
                break;
            }
            default:
                break;
        }
    }

    void final(void *digest) {
        switch (_hash) {
            case SHA256: {
                SHA256::final(_sha256_ctx, digest);
                break;
            } case SHA1: {
                SHA1::final(_sha1_ctx, digest);
                break;
            }
            default:
                break;
        }
    }

    static void hash(hash_t hash, const void *data, size_t len, void *digest, uint32_t num_iter=1) {
        num_iter = num_iter == 0 ? 1 : num_iter;
        Hash h(hash);
        h.init();
        h.update(data, len);
        h.final(digest);
        for (uint32_t i = 1; i < num_iter; ++i) {
            h.init();
            h.update(digest, h.hash_size());
            h.final(digest);
        }
    }

private:

    const hash_t _hash;

    SHA256::context _sha256_ctx = { 0 };

    SHA1::context _sha1_ctx = { 0 };

};

#endif // __HASH_HPP
