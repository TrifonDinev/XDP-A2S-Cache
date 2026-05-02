#pragma once

#include <stdbool.h>

#include "xdp.h"

typedef struct
{
  struct xdp_program *prog;
  struct sockaddr_in *servers;
  char *ifname;
  pthread_t query_tid;
  xdp_maps_t xdp_maps;
  unsigned int ifindex;
  int server_count;
  _Atomic bool running;
} loader_ctx_t;

void cleanup(loader_ctx_t *ctx);
bool parse_config_file(loader_ctx_t *ctx, const char *filename);
void termination_handler(loader_ctx_t *ctx, int sig);
void *a2s_query_servers(void *arg);