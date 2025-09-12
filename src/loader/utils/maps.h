#pragma once

struct xdp_program;

typedef struct xdp_maps
{
  int a2s_info;
  int a2s_players;
  int a2s_rules;
} xdp_maps_t;

void get_maps(struct xdp_program *, xdp_maps_t *);