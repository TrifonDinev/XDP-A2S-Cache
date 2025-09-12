#pragma once

#include "maps.h"
#include "socket.h"

struct server
{
  char *ip;
  int port;
};

struct server_config
{
  struct server *servers;
  int server_count;
};

typedef struct
{
  xdp_maps_t *xdp_maps;
  struct server_config *config;
} thread_args_t;

void *a2s_query_servers(void *args);