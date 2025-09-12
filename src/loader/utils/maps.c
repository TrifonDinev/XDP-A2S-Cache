#include <xdp/libxdp.h>
#include <stdlib.h>

#include "maps.h"

void get_maps(struct xdp_program *prog, xdp_maps_t *xdp_maps)
{
  // Get bpf object
  struct bpf_object *bpf_obj = xdp_program__bpf_obj(prog);

  // Get maps
  xdp_maps->a2s_info = bpf_object__find_map_fd_by_name(bpf_obj, "a2s_info");
  xdp_maps->a2s_players = bpf_object__find_map_fd_by_name(bpf_obj, "a2s_players");
  xdp_maps->a2s_rules = bpf_object__find_map_fd_by_name(bpf_obj, "a2s_rules");
}