#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <pthread.h>

#include "utils/xdp.h"
#include "utils/maps.h"
#include "utils/a2s_query_servers.h"
#include "utils/helpers.h"

char *interface = NULL;
int ifidx;
struct xdp_program *prog = NULL;
struct server_config cfg = {0};

int main()
{
  // Load the configuration to get the interface name and servers
  parse_config_file(&cfg);

  // Initialize and bind to the interface (after getting the interface name from the config)
  ifidx = if_nametoindex(interface);
  if (ifidx == 0)
  {
    fprintf(stderr, "ERROR: failed to get interface index: %s\n", strerror(errno));
    cleanup();
    return EXIT_FAILURE;
  }

  // Load the BPF object for XDP program
  prog = load_bpf_object("/etc/xdpa2scache/xdpa2scache.o");
  if (!prog)
  {
    fprintf(stderr, "ERROR: failed to load bpf object file\n");
    cleanup();
    return EXIT_FAILURE;
  }

  // Attach XDP program
  if (attach_xdp(prog, ifidx, 0))
  {
    cleanup();
    return EXIT_FAILURE;
  }

  // Create an xdpmaps pointer
  xdp_maps_t xdp_maps;

  // Get maps from the xdp program into userspace program
  get_maps(prog, &xdp_maps);

  // Hook sigint and sigterm for gracefully removing the program
  signal(SIGINT, termination_handler);
  signal(SIGTERM, termination_handler);

  // Create a thread for gathering from the server
  pthread_t thread_id;
  thread_args_t args = {.xdp_maps = &xdp_maps, .config = &cfg};

  if (pthread_create(&thread_id, NULL, a2s_query_servers, &args) != 0)
  {
    fprintf(stderr, "ERROR: failed to create thread\n");
    cleanup();
    return EXIT_FAILURE;
  }

  // Detach the thread so that its resources are cleaned up automatically
  pthread_detach(thread_id);

  // Keep the program running
  pause();
}
