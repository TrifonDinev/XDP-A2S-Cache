#pragma once

#define CONNECTIONLESS_HEADER   0xFFFFFFFF
#define A2S_MIN_SIZE            5
#define A2S_MAX_SIZE            1400

#define A2S_INFO                0x54
#define S2A_INFO_SRC            0x49
#define A2S_PLAYER              0x55
#define S2A_PLAYER              0x44
#define A2S_RULES               0x56
#define S2A_RULES               0x45
#define S2C_CHALLENGE           0x41

#define A2S_INFO_REQ            "\xFF\xFF\xFF\xFF\x54Source Engine Query\0"
#define A2S_INFO_REQ_SIZE       (sizeof(A2S_INFO_REQ) - 1)

#define A2S_PLAYER_REQ          "\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF"
#define A2S_PLAYER_REQ_SIZE     (sizeof(A2S_PLAYER_REQ) - 1)

#define A2S_RULES_REQ           "\xFF\xFF\xFF\xFF\x56\xFF\xFF\xFF\xFF"
#define A2S_RULES_REQ_SIZE      (sizeof(A2S_RULES_REQ) - 1)

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