#pragma once

// Hash key injected from userspace before loading
const __u64 hash_key SEC(".rodata.hash_key") = 0;

/**
* Computes a 32-bit hash from IPv4/UDP 4-tuple and a hash key
*
* @param saddr Source IPv4 address.
* @param daddr Destination IPv4 address.
* @param sport Source UDP port.
* @param dport Destination UDP port.
*
* @return 32-bit computed hash value.
*/
static __always_inline __u32 cookie_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport)
{
  __u32 hash = saddr ^ daddr ^ ((__u32)sport << 16) ^ dport;

  hash ^= (hash >> 16);
  hash += (hash << 7);

  // Manually unrolled loop: Process 4 pairs of bytes from the key and update the hash
  hash += ((__u8)(hash_key) ^ (__u8)(hash_key >> 8));
  hash ^= (hash >> 11);
  hash += (hash << 15);

  hash += ((__u8)(hash_key >> 16) ^ (__u8)(hash_key >> 24));
  hash ^= (hash >> 11);
  hash += (hash << 15);

  hash += ((__u8)(hash_key >> 32) ^ (__u8)(hash_key >> 40));
  hash ^= (hash >> 11);
  hash += (hash << 15);

  hash += ((__u8)(hash_key >> 48) ^ (__u8)(hash_key >> 56));
  hash ^= (hash >> 11);
  hash += (hash << 15);

  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  return hash;
}

/**
* Creates a cookie from IP/UDP headers and the hash key
*
* @param iph Pointer to IPv4 header.
* @param udph Pointer to UDP header.
*
* @return __u32 The generated cookie.
*/
static __always_inline __u32 create_cookie(struct iphdr *iph, struct udphdr *udph)
{
  return cookie_hash(iph->saddr, iph->daddr, udph->source, udph->dest);
}

/**
* Checks if the cookie is valid for the current packet
*
* @param iph Pointer to IPv4 header.
* @param udph Pointer to UDP header.
* @param check The cookie value to validate.
*
* @return true If the cookie is correct.
* @return false If the cookie is incorrect.
*/
static __always_inline bool check_cookie(struct iphdr *iph, struct udphdr *udph, __u32 check)
{
  return create_cookie(iph, udph) == check;
}