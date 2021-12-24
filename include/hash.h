#ifndef _LINUX_HASH_H
#define _LINUX_HASH_H
/* Fast hashing routine for ints,  longs and pointers.
   (C) 2002 Nadia Yvette Chambers, IBM */

#ifdef __GLIBC__
#include <bits/wordsize.h>
#else
#include <bits/reg.h>
#endif
#include <linux/stddef.h>
#include <sys/types.h>
#include <stdint.h>

/*
 * The "GOLDEN_RATIO_PRIME" is used in ifs/btrfs/brtfs_inode.h and
 * fs/inode.c.  It's not actually prime any more (the previous primes
 * were actively bad for hashing), but the name remains.
 */
#if __WORDSIZE == 32
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_32
#define hash_long(val, bits) hash_32(val, bits)
#elif __WORDSIZE == 64
#define hash_long(val, bits) hash_64(val, bits)
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_64
#else
#error Wordsize not 32 or 64
#endif

/* String based hash function */
static uint32_t inline hash(const char *key, unsigned int size)
{
	u_int32_t hashval;
	char *s = (char *) key;

	for (hashval = 0; *s != '\0';) {
		hashval += (unsigned char) *s++;
		hashval += (hashval << 10);
		hashval ^= (hashval >> 6);
	}

	hashval += (hashval << 3);
	hashval ^= (hashval >> 11);
	hashval += (hashval << 15);

	return hashval % size;
}

/*
 * This hash multiplies the input by a large odd number and takes the
 * high bits.  Since multiplication propagates changes to the most
 * significant end only, it is essential that the high bits of the
 * product be used for the hash value.
 *
 * Chuck Lever verified the effectiveness of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf
 *
 * Although a random odd number will do, it turns out that the golden
 * ratio phi = (sqrt(5)-1)/2, or its negative, has particularly nice
 * properties.  (See Knuth vol 3, section 6.4, exercise 9.)
 *
 * These are the negative, (1 - phi) = phi**2 = (3 - sqrt(5))/2,
 * which is very slightly easier to multiply by and makes no
 * difference to the hash distribution.
 */
#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

static inline uint32_t __hash_32(uint32_t val)
{
	return val * GOLDEN_RATIO_32;
}

static inline uint32_t hash_32(uint32_t val, unsigned int bits)
{
	/* High bits are more random, so use them. */
	return __hash_32(val) >> (32 - bits);
}

static __always_inline uint32_t hash_64(uint64_t val, unsigned int bits)
{
#if __WORDSIZE == 64
	/* 64x64-bit multiply is efficient on all 64-bit processors */
	return val * GOLDEN_RATIO_64 >> (64 - bits);
#else
	/* Hash 64 bits using only 32x32-bit multiply. */
	return hash_32((uint32_t) val ^ __hash_32(val >> 32), bits);
#endif
}

static inline uint32_t hash_ptr(const void *ptr, unsigned int bits)
{
	return hash_long((unsigned long) ptr, bits);
}

/* This really should be called fold32_ptr; it does no hashing to speak of. */
static inline uint32_t hash32_ptr(const void *ptr)
{
	unsigned long val = (unsigned long) ptr;

#if __WORDSIZE == 64
	val ^= (val >> 32);
#endif
	return (uint32_t) val;
}

#endif /* _LINUX_HASH_H */
