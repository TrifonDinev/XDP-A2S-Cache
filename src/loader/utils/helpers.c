#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pthread.h>
#include <libconfig.h>
#include <xdp/libxdp.h>

#include "helpers.h"

/**
* Free dynamically allocated memory and reset server configuration (server count and server list)
*
* @param ctx Pointer to the loader context.
*/
void cleanup(loader_ctx_t *ctx)
{
  fprintf(stderr, "Starting resource cleanup...\n");

  // Check if interface name exists before freeing
  if (ctx->ifname)
  {
    fprintf(stderr, "Cleaning up loader context for interface: %s...\n", ctx->ifname);
    free(ctx->ifname);
    ctx->ifname = NULL;
    ctx->ifindex = 0;
  }
  else
  {
    fprintf(stderr, "Cleaning up uninitialized/empty loader interface context...\n");
  }

  // Check if server list exists and free each IP string
  if (ctx->servers)
  {
    fprintf(stderr, "Cleaning up %d configured servers...\n", ctx->server_count);
    free(ctx->servers);
    ctx->servers = NULL;
    fprintf(stderr, "Server array memory released.\n");
  }

  ctx->server_count = 0;
  fprintf(stderr, "Cleanup finished successfully.\n");
}

/**
* Parse the configuration file to retrieve the network interface and server details (IP and port)
* Populate the cfg structure with the parsed data
*
* @param ctx Pointer to the context to populate.
* @param filename Path to the configuration file.
* @return true on success, or false on parsing or validation failure.
*/
bool parse_config_file(loader_ctx_t *ctx, const char *filename)
{
  config_t config;
  config_init(&config);

  // Check if the configuration file can be read and parsed
  if (!config_read_file(&config, filename))
  {
    fprintf(stderr, "%s:%d - %s\n - Config file is missing!\n",
    config_error_file(&config),
    config_error_line(&config),
    config_error_text(&config));
    config_destroy(&config);
    return false;
  }

  // Check if the interface setting is present
  const char *interface_temp;
  if (config_lookup_string(&config, "interface", &interface_temp) != CONFIG_TRUE)
  {
    fprintf(stderr, "No 'interface' setting in configuration file.\n");
    config_destroy(&config);
    return false;
  }

  // Check if the interface name isn't just an empty string
  if (interface_temp[0] == '\0')
  {
    fprintf(stderr, "The 'interface' setting is empty in configuration file.\n");
    config_destroy(&config);
    return false;
  }

  // Check if the network interface is valid
  if ((ctx->ifindex = if_nametoindex(interface_temp)) == 0)
  {
    fprintf(stderr, "ERROR: Interface '%s' not found: %s\n", interface_temp, strerror(errno));
    config_destroy(&config);
    return false;
  }

  // Check if memory allocation for the interface name failed
  if (!(ctx->ifname = strdup(interface_temp)))
  {
    fprintf(stderr, "Memory allocation failed for interface.\n");
    config_destroy(&config);
    return false;
  }

  // Check if there are any servers defined in the config
  config_setting_t *servers = config_lookup(&config, "servers");
  int count = (servers) ? config_setting_length(servers) : 0;

  if (count <= 0)
  {
    fprintf(stderr, "No servers configured in the 'servers' setting.\n");
    config_destroy(&config);
    return false;
  }

  // Check if memory allocation for servers failed
  if (!(ctx->servers = calloc(count, sizeof(struct sockaddr_in))))
  {
    fprintf(stderr, "Memory allocation failed for servers array.\n");
    config_destroy(&config);
    return false;
  }

  // Set count to 0 and increment it as we successfully load each server
  ctx->server_count = 0;

  // Process and validate each server from the configuration
  for (int i = 0; i < count; i++)
  {
    config_setting_t *server_cfg = config_setting_get_elem(servers, i);
    const char *ip_str;
    int port_val;

    // Each server must have both an IP and a port
    if (!(config_setting_lookup_string(server_cfg, "ip", &ip_str) && config_setting_lookup_int(server_cfg, "port", &port_val)))
    {
      fprintf(stderr, "Invalid 'server' setting at index %d. Skipping...\n", i);
      continue;
    }

    // Prepare address structure in network byte order
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port_val) };

    // Validate IP address
    if (inet_pton(AF_INET, ip_str, &addr.sin_addr) <= 0)
    {
      fprintf(stderr, "Invalid IP address format: %s. Skipping index %d...\n", ip_str, i);
      continue;
    }

    // Validate Port
    if (port_val < 1 || port_val > 65535)
    {
      fprintf(stderr, "ERROR: Invalid port %d at index %d (must be 1-65535). Skipping...\n", port_val, i);
      continue;
    }

    // Duplicate check
    bool is_duplicate = false;

    for (int j = 0; j < ctx->server_count; j++)
    {
      if (ctx->servers[j].sin_addr.s_addr == addr.sin_addr.s_addr && ctx->servers[j].sin_port == addr.sin_port)
      {
        is_duplicate = true;
        break;
      }
    }

    if (is_duplicate)
    {
      fprintf(stderr, "Duplicate server found: %s:%d. Skipping index %d...\n", ip_str, port_val, i);
      continue;
    }

    ctx->servers[ctx->server_count++] = addr;
  }

  // Memory optimization (shrink) if duplicates were removed
  if (ctx->server_count < count && ctx->server_count > 0)
  {
    struct sockaddr_in *temp = realloc(ctx->servers, ctx->server_count * sizeof(struct sockaddr_in));

    if (temp)
    {
      ctx->servers = temp;
    }
    else
    {
      fprintf(stderr, "Warning: Could not shrink server list memory, using original allocation.\n");
    }
  }
  else if (ctx->server_count == 0)
  {
    fprintf(stderr, "No valid servers were loaded from configuration.\n");
    config_destroy(&config);
    return false;
  }

  // Print how much servers we loaded from the configuration
  printf(ctx->server_count == 1 ? "Loaded 1 server from configuration.\n" : "Loaded %d servers from configuration.\n", ctx->server_count);

  config_destroy(&config);
  return true;
}

/**
* Handle termination signals to gracefully stop the query thread, detach the XDP program, close resources, and clean up before exiting
*
* @param ctx Pointer to the loader context.
* @param sig Signal number received (0 for fatal errors).
*/
void termination_handler(loader_ctx_t *ctx, int sig)
{
  // Don't try another shutdown if one is already in progress
  if (!ctx->running)
  {
    printf("\r[!] Already shutting down, please wait...\n");
    return;
  }

  // Print that termination signal has been received
  if (sig)
  {
    printf("\rReceived %s (signal %d). Starting graceful shutdown...\n", strsignal(sig), sig);
  }

  // Stop the background query thread
  ctx->running = false;

  // Wait for the background query thread to finish
  if (ctx->query_tid)
  {
    // We can't wait for ourselves (prevent freeze)
    if (!pthread_equal(pthread_self(), ctx->query_tid))
    {
      // When shutdown from main thread (signal)
      printf("Waiting for background query thread to exit...\n");
      pthread_join(ctx->query_tid, NULL);
      printf("Background query thread exited. Cleaning up resources...\n");
    }
    else
    {
      // When shutdown from background query thread (internal/error)
      printf("Internal shutdown from background query thread. Cleaning up resources...\n");
    }

    // Set query thread ID to 0
    ctx->query_tid = 0;
  }

  // Detach XDP program
  if (ctx->prog)
  {
    if (ctx->ifindex > 0)
    {
      detach_xdp(ctx->prog, ctx->ifindex);
    }

    // Close XDP program and clean up memory
    xdp_program__close(ctx->prog);
    ctx->prog = NULL;
  }

  // Cleanup resources
  cleanup(ctx);

  // Final confirmation before exiting
  printf("Shutdown complete.\n");

  // Exit program
  exit(sig == 0 ? EXIT_FAILURE : EXIT_SUCCESS);
}