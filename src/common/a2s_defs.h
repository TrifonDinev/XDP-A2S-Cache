#pragma once

// Don't enable it unless you want to see something or debug!
//#define A2S_DEBUG

#define A2S_MAX_SIZE 1400
#define A2S_CHALLENGE 0x41
#define A2S_INFO 0x54
#define A2S_PLAYERS 0x55
#define A2S_RULES 0x56

struct a2s_val
{
  __u64 size;
  unsigned char data[A2S_MAX_SIZE];
};

struct a2s_server_key
{
  __be32 ip;
  __be16 port;
};