#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libconfig.h>

#include "helpers.h"
#include "maps.h"
#include "xdp.h"

extern char *interface;
extern int ifidx;
extern struct xdp_program *prog;
extern struct server_config cfg;

// Free dynamically allocated memory and reset server configuration (server count and server list)
void cleanup()
{
  if (interface)
  {
    free(interface);
    interface = NULL;
  }
  
  if (cfg.servers)
  {
    for (int i = 0; i < cfg.server_count; i++)
    {
      free(cfg.servers[i].ip);
    }
    
    free(cfg.servers);
    cfg.servers = NULL;
    cfg.server_count = 0;
  }
}

// Parse the configuration file to retrieve the network interface and server details (IP and port)
// Populate the cfg structure with the parsed data
void parse_config_file(struct server_config *cfg)
{
  const char *filename = "/etc/xdpa2scache/config";
  config_t config;
  config_init(&config);

  if (!config_read_file(&config, filename))
  {
    fprintf(stderr, "%s:%d - %s\n - Config file is missing!\n",
    config_error_file(&config),
    config_error_line(&config),
    config_error_text(&config));
    config_destroy(&config);
    exit(EXIT_FAILURE);
  }

  const char *interface_temp;
  if (config_lookup_string(&config, "interface", &interface_temp) != CONFIG_TRUE)
  {
    fprintf(stderr, "No 'interface' setting in configuration file.\n");
    config_destroy(&config);
    exit(EXIT_FAILURE);
  }

  interface = strdup(interface_temp);
  if (!interface)
  {
    fprintf(stderr, "Memory allocation failed for interface.\n");
    config_destroy(&config);
    exit(EXIT_FAILURE);
  }

  config_setting_t *servers = config_lookup(&config, "servers");
  if (!servers)
  {
    fprintf(stderr, "No 'servers' setting in configuration file.\n");
    config_destroy(&config);
    cleanup();
    exit(EXIT_FAILURE);
  }

  int count = config_setting_length(servers);
  if (count == 0)
  {
    fprintf(stderr, "No servers configured in the 'servers' setting.\n");
    config_destroy(&config);
    cleanup();
    exit(EXIT_FAILURE);
  }

  cfg->servers = malloc(count * sizeof(struct server));
  if (!cfg->servers)
  {
    fprintf(stderr, "Memory allocation failed for servers array.\n");
    config_destroy(&config);
    cleanup();
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < count; i++)
  {
    config_setting_t *server = config_setting_get_elem(servers, i);
    const char *ip_temp;
    int port;

    if (!(config_setting_lookup_string(server, "ip", &ip_temp) && config_setting_lookup_int(server, "port", &port)))
    {
      fprintf(stderr, "Invalid 'server' setting at index %d.\n", i);
      
      for (int j = 0; j < i; j++)
      {
        free(cfg->servers[j].ip);
      }

      free(cfg->servers);
      cfg->servers = NULL;
      cfg->server_count = 0;

      config_destroy(&config);
      cleanup();
      exit(EXIT_FAILURE);
    }

    cfg->servers[i].ip = strdup(ip_temp);
    if (!cfg->servers[i].ip)
    {
      fprintf(stderr, "Memory allocation failed for server IP at index %d.\n", i);

      for (int j = 0; j < i; j++)
      {
        free(cfg->servers[j].ip);
      }

      free(cfg->servers);
      cfg->servers = NULL;
      cfg->server_count = 0;

      config_destroy(&config);
      cleanup();
      exit(EXIT_FAILURE);
    }

    cfg->servers[i].port = port;
  }

  // Print how much servers we loaded from the configuration.
  cfg->server_count = count;
  printf(count == 1 ? "Loaded 1 server from configuration.\n" : "Loaded %d servers from configuration.\n", count);

  config_destroy(&config);
}

// Handle termination signals to gracefully detach the XDP program, close resources, and clean up before exiting
void termination_handler()
{
  if (detach_xdp(ifidx, prog) < 0)
  {
    fprintf(stderr, "ERROR: failed to detach xdp program from interface\n");
  }

  xdp_program__close(prog);
  cleanup();
  exit(EXIT_SUCCESS);
}
