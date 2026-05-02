#pragma once

struct xdp_program *load_bpf_object(const char *filename);
int attach_xdp(struct xdp_program *prog, unsigned int ifindex, int detach);
int detach_xdp(struct xdp_program *prog, unsigned int ifindex);

typedef struct xdp_maps
{
  int a2s_info;
  int a2s_player;
  int a2s_rules;
} xdp_maps_t;

int get_maps(struct xdp_program *prog, xdp_maps_t *xdp_maps);