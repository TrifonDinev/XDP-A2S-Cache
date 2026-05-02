#pragma once

#ifdef likely
    #undef likely
#endif
#define likely(x) __builtin_expect(!!(x), 1)

#ifdef unlikely
    #undef unlikely
#endif
#define unlikely(x) __builtin_expect(!!(x), 0)

#ifdef htons
    #undef htons
#endif
#ifdef ntohs
    #undef ntohs
#endif
#ifdef htonl
    #undef htonl
#endif
#ifdef ntohl
    #undef ntohl
#endif

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

#ifdef memcpy
  #undef memcpy
#endif
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))