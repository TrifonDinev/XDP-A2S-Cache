#pragma once

// The key and the cookie_hash function is not the perfect and the best idea, but I have no better idea for the moment
// If you have better idea for this, please do a PR (https://github.com/TrifonDinev/xdp-a2s-cache) or contact me (https://trifondinev.com)

static __u8 key[8] = {0};
static __u8 key_initialized = 0;

static __always_inline __u32 cookie_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport)
{
  // Check if the key is not initialized and initialize it if it is not
  if (!key_initialized)
  {
    // Get current timestamp in nanoseconds and use it as simple seed
    __u64 timestamp = bpf_ktime_get_ns();

    // XOR the upper and lower 32 bits of the timestamp, then mask to get the lower 32 bits as the seed
    __u32 seed = (timestamp ^ (timestamp >> 32)) & 0xFFFFFFFF;

    // Mix the seed once before entering the loop for key generation
    seed ^= (seed << 5);
    seed ^= (seed >> 7);
    seed ^= (seed << 11);

    // Store the mixed seed in the key array
    for (int i = 0; i < 8; i++)
    {
      // Scramble the seed and assign the least significant byte to each key[i]
      key[i] = (seed ^ (seed >> 8)) & 0xFF;
    }

    // Flag as initialized
    key_initialized = 1;
  }

  // Use local variables to help compiler with register allocation
  __u32 hash = saddr ^ daddr ^ sport ^ dport;

  // Fast mixing for fields
  hash ^= (hash >> 16);
  hash += (hash << 7);

  // Manually unrolled loop: Process 4 pairs of bytes from the key and update the hash
  hash += (key[0] ^ key[1]);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  hash += (key[2] ^ key[3]);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  hash += (key[4] ^ key[5]);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  hash += (key[6] ^ key[7]);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  // Final mixing for better distribution
  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  return hash;
}

static __always_inline __u32 create_cookie(struct iphdr *iph, struct udphdr *udph)
{
  return cookie_hash(iph->saddr, iph->daddr, udph->source, udph->dest);
}

static __always_inline bool check_cookie(struct iphdr *iph, struct udphdr *udph, __u32 check)
{
  return create_cookie(iph, udph) == check;
}