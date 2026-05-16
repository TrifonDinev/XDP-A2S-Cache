#include <errno.h>
#include <net/if.h>
#include <xdp/libxdp.h>

#include "xdp.h"

/**
* Loads a BPF object file and returns the associated XDP program
*
* @param filename Path to the BPF object file.
* @return Pointer to the loaded XDP program, or NULL on failure.
*/
struct xdp_program *load_bpf_object(const char *filename)
{
  struct xdp_program *prog = NULL;

  // Define options for opening the BPF object
  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts, .pin_root_path = "/sys/fs/bpf");

  // Attempt to open the XDP program from the given BPF object file
  prog = xdp_program__open_file(filename, NULL, &opts);

  if (!prog)
  {
    fprintf(stderr, "ERROR: Failed to load BPF object file '%s': %s\n", filename, strerror(errno));
    return NULL;
  }

  return prog;
}

/**
* Attach or detach an XDP program to an interface
*
* @param prog XDP program.
* @param ifindex Interface index.
* @param detach Whether to detach (non-zero) or attach (zero).
* @return 0 on success, or a negative error code on failure.
*/
int attach_xdp(struct xdp_program *prog, unsigned int ifindex, int detach)
{
  int err = -EINVAL;
  static const struct
  {
    enum xdp_attach_mode mode;
    const char *name;
  } modes[] =
  {
    { XDP_MODE_NATIVE, "DRV/native" },
    { XDP_MODE_SKB, "SKB/generic" }
  };

  // Set program priority and chain continuation before attaching
  if (!detach)
  {
    xdp_program__set_run_prio(prog, XDP_MULTIPROG_PRIORITY);
    xdp_program__set_chain_call_enabled(prog, XDP_MULTIPROG_ACTION, XDP_MULTIPROG_ENABLED);
  }

  // Try to attach/detach using available modes (Native then Generic)
  for (int i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
  {
    err = detach ? xdp_program__detach(prog, ifindex, modes[i].mode, 0) : xdp_program__attach(prog, ifindex, modes[i].mode, 0);

    if (err == 0)
    {
      char ifname[IF_NAMESIZE];
      if (!if_indextoname(ifindex, ifname)) snprintf(ifname, IF_NAMESIZE, "idx %u", ifindex);

      fprintf(stdout, "Successfully %s XDP program on %s interface with %s mode.\n", detach ? "detached" : "attached", ifname, modes[i].name);
      return 0;
    }

    // Exit if the error is critical (e.g., permissions or missing interface)
    if (err != -EOPNOTSUPP && err != -ENOTSUP)
    break;
  }

  // Log error only after all attempts fail
  char ifname[IF_NAMESIZE];
  if (!if_indextoname(ifindex, ifname)) snprintf(ifname, IF_NAMESIZE, "idx %u", ifindex);
  fprintf(stderr, "Error %s XDP program on %s interface: %s (code %d)\n", detach ? "detaching" : "attaching", ifname, strerror(-err), err);

  return err;
}

/**
* Detach the XDP program from the interface
*
* @param prog XDP program.
* @param ifindex Interface index.
* @return 0 on success, or a negative error code on failure.
*/
int detach_xdp(struct xdp_program *prog, unsigned int ifindex)
{
  // Detach the XDP program from the interface
  int err = xdp_program__detach(prog, ifindex, XDP_MODE_UNSPEC, 0);

  if (err < 0)
  {
    char ifname[IF_NAMESIZE];
    if (!if_indextoname(ifindex, ifname)) snprintf(ifname, IF_NAMESIZE, "idx %u", ifindex);

    fprintf(stderr, "Error detaching XDP from %s interface: %s (code %d)\n", ifname, strerror(-err), err);
    return err;
  }

  printf("Successfully detached XDP program.\n");
  return 0;
}

/**
* Retrieves file descriptors (FDs) for specific BPF maps from the loaded XDP program
*
* @param prog Pointer to the loaded XDP program object.
* @param xdp_maps Structure where the retrieved map FDs will be stored.
* @return 0 on success, or a negative error code on failure.
*/
int get_maps(struct xdp_program *prog, xdp_maps_t *xdp_maps)
{
  // Get the BPF object from the XDP program
  struct bpf_object *bpf_obj = xdp_program__bpf_obj(prog);
  int err;

  xdp_maps->a2s_info = bpf_object__find_map_fd_by_name(bpf_obj, "a2s_info");

  if (xdp_maps->a2s_info < 0)
  {
    err = xdp_maps->a2s_info;
    fprintf(stderr, "ERROR: Could not find BPF map 'a2s_info': %s (code %d)\n", strerror(-err), err);
    return err;
  }

  #ifdef A2S_PLAYER_ENABLE
  xdp_maps->a2s_player = bpf_object__find_map_fd_by_name(bpf_obj, "a2s_player");

  if (xdp_maps->a2s_player < 0)
  {
    err = xdp_maps->a2s_player;
    fprintf(stderr, "ERROR: Could not find BPF map 'a2s_player': %s (code %d)\n", strerror(-err), err);
    return err;
  }
  #endif

  #ifdef A2S_RULES_ENABLE
  xdp_maps->a2s_rules = bpf_object__find_map_fd_by_name(bpf_obj, "a2s_rules");

  if (xdp_maps->a2s_rules < 0)
  {
    err = xdp_maps->a2s_rules;
    fprintf(stderr, "ERROR: Could not find BPF map 'a2s_rules': %s (code %d)\n", strerror(-err), err);
    return err;
  }
  #endif

  return 0;
}

/**
* Generates a key via hardware RDRAND and injects it into the eBPF object
*
* @param prog Pointer to the loaded XDP program object.
* @return 0 on success, or a negative error code on failure.
*/
int generate_and_inject_hash_key(struct xdp_program *prog)
{
  // Get the BPF object from the XDP program
  struct bpf_object *bpf_obj = xdp_program__bpf_obj(prog);

  // Generate a hardware random key
  uint64_t final_key;

  __asm__ __volatile__(
    "rdtsc; rdrand %0"
    : "=r" (final_key)
    :
    : "rax", "rdx", "cc"
  );

  // Try to find the dedicated map by full name
  struct bpf_map *key_map = bpf_object__find_map_by_name(bpf_obj, "xdpa2scache.rodata.hash_key");

  // If not found, try the fallback short name or both options failed, resolve the error and exit
  if (!key_map && !(key_map = bpf_object__find_map_by_name(bpf_obj, ".rodata.hash_key")))
  {
    int err = libbpf_get_error(key_map) ?: -ENOENT;
    fprintf(stderr, "ERROR: Dedicated key section map not found: %s (code %d)\n", strerror(-err), err);
    return err;
  }

  // Inject the key
  int err = bpf_map__set_initial_value(key_map, &final_key, sizeof(final_key));

  if (err < 0)
  {
    fprintf(stderr, "ERROR: Failed to inject hardware key: %s (code %d)\n", strerror(-err), err);
    return err;
  }

  printf("Hash Key injected successfully into %s.\n", bpf_map__name(key_map));
  return 0;
}