#include <stdio.h>
#include <signal.h>
#include <pthread.h>

#include "utils/helpers.h"

int main()
{
  // Initialize the loader context structure
  loader_ctx_t ctx = { .running = true, .ifname = NULL, .prog = NULL };

  // Block signals before creating threads so they inherit the mask
  sigset_t sig_set;
  sigemptyset(&sig_set);
  sigaddset(&sig_set, SIGINT);
  sigaddset(&sig_set, SIGTERM);

  if (pthread_sigmask(SIG_BLOCK, &sig_set, NULL) != 0)
  {
    fprintf(stderr, "FATAL: Failed to block signals. Aborting...\n");
    termination_handler(&ctx, 0);
  }

  // Parse the configuration to get the interface name and servers
  if (!parse_config_file(&ctx, "/etc/xdpa2scache/config"))
  {
    fprintf(stderr, "FATAL: Configuration parsing failed. Aborting...\n");
    termination_handler(&ctx, 0);
  }

  // Load the BPF object for XDP program
  if (!(ctx.prog = load_bpf_object("/etc/xdpa2scache/xdpa2scache.o")))
  {
    fprintf(stderr, "FATAL: BPF object initialization failed. Aborting...\n");
    termination_handler(&ctx, 0);
  }

  // Attach XDP program to the network interface
  if (attach_xdp(ctx.prog, ctx.ifindex, 0) != 0)
  {
    fprintf(stderr, "FATAL: XDP attachment failed. Aborting...\n");
    termination_handler(&ctx, 0);
  }

  // Get maps from the xdp program into userspace program
  if (get_maps(ctx.prog, &ctx.xdp_maps) < 0)
  {
    fprintf(stderr, "FATAL: BPF maps initialization failed. Aborting...\n");
    termination_handler(&ctx, 0);
  }

  // Create a query thread for gathering data from the server(s)
  if (pthread_create(&ctx.query_tid, NULL, a2s_query_servers, &ctx) != 0)
  {
    fprintf(stderr, "FATAL: Query thread creation failed. Aborting...\n");
    termination_handler(&ctx, 0);
  }

  // Wait for a termination signal synchronously
  int sig_received;
  if (sigwait(&sig_set, &sig_received) != 0)
  {
    fprintf(stderr, "FATAL: sigwait failed. Aborting...\n");
    termination_handler(&ctx, 0);
  }

  // Clean up resources and shut down
  termination_handler(&ctx, sig_received);
}