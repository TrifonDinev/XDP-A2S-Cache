#pragma once

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#ifdef __BPF__
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#define htons(x) ((__be16)__builtin_bswap16((x)))
#define ntohs(x) ((__be16)__builtin_bswap16((x)))
#define htonl(x) ((__be32)__builtin_bswap32((x)))
#define ntohl(x) ((__be32)__builtin_bswap32((x)))

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(x) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif