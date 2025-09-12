#pragma once

/*
 * Due to BPF_MAP_TYPE_HASH and the overall working logic of the A2S cache I wanted:
 * If you spawn servers on random ports or you need more keys/ip/ports, please rise the max_entries of the A2S_ things.
 * Currently, my idea is 1024, which we can't run more than 40-100 servers on one machine for example, so 1024 is more than fine.
 * (!) If we use, for example, port range 27000-28000, that's 1000 servers, 1024 should be okay.
 * (!) If we use, for example, port range 27000-30000, that's 3000 servers, 3000 + a bit more, let's say 3024, just to be sure. and so on...
*/

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct a2s_server_key);
  __type(value, struct a2s_val);
  __uint(max_entries, 1024);
} a2s_info SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct a2s_server_key);
  __type(value, struct a2s_val);
  __uint(max_entries, 1024);
} a2s_players SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct a2s_server_key);
  __type(value, struct a2s_val);
  __uint(max_entries, 1024);
} a2s_rules SEC(".maps");