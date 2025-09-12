#pragma once

#include <xdp/libxdp.h>

struct xdp_program *load_bpf_object(const char *filename);
int attach_xdp(struct xdp_program *prog, int ifidx, __u8 detach);
int detach_xdp(int ifidx, struct xdp_program *prog);