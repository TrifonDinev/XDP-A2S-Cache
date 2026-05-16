#pragma once

#include "config.h"

struct xdp_program *load_bpf_object(const char *filename);
int attach_xdp(struct xdp_program *prog, unsigned int ifindex, int detach);
int detach_xdp(struct xdp_program *prog, unsigned int ifindex);

typedef struct xdp_maps
{
  int a2s_info;

  #ifdef A2S_PLAYER_ENABLE
  int a2s_player;
  #endif

  #ifdef A2S_RULES_ENABLE
  int a2s_rules;
  #endif
} xdp_maps_t;

int get_maps(struct xdp_program *prog, xdp_maps_t *xdp_maps);
int generate_and_inject_hash_key(struct xdp_program *prog);