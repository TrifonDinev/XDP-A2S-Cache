#include <errno.h>

#include "xdp.h"

/**
* Loads a BPF object file and returns the associated XDP program.
*
* @param filename Path to the BPF object file.
* @return Pointer to the loaded XDP program, or NULL on failure.
*/
struct xdp_program *load_bpf_object(const char *filename)
{
  struct xdp_program *prog = NULL;

  // Define options for opening the BPF object
  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
    .pin_root_path = "/sys/fs/bpf",
    .kconfig = NULL
  );

  // Attempt to open the XDP program from the given BPF object file
  prog = xdp_program__open_file(filename, NULL, &opts);

  if (!prog)
  {
    fprintf(stderr, "ERROR: Failed to load BPF object file '%s': %s\n",
    filename, strerror(errno));
    return NULL;
  }

  return prog;
}

/**
* Attach or detach an XDP program to an interface.
*
* @param prog XDP program.
* @param ifidx Interface index.
* @param detach Whether to detach (non-zero) or attach (zero).
* @return 0 on success, 1 on failure.
*/
int attach_xdp(struct xdp_program *prog, int ifidx, __u8 detach)
{
  int err;
  __u32 mode = XDP_MODE_NATIVE;
  const char *mode_str = "DRV/native";

  while (1)
  {
    err = detach ? xdp_program__detach(prog, ifidx, mode, 0) : xdp_program__attach(prog, ifidx, mode, 0);

    if (err)
    {
      fprintf(stderr, "Error %s XDP program with mode %s: %s (%d)\n", detach ? "detaching": "attaching", mode_str, strerror(-err), -err);

      switch (mode)
      {
        case XDP_MODE_HW:
        mode = XDP_MODE_NATIVE;
        mode_str = "DRV/native";
        break;

        case XDP_MODE_NATIVE:
        mode = XDP_MODE_SKB;
        mode_str = "SKB/generic";
        break;

        case XDP_MODE_SKB:
        fprintf(stderr, "Error: No more modes to try for XDP program.\n");
        return 1;
      }
      continue;
    }
    break;
  }

  fprintf(stdout, "Successfully %s XDP program with mode %s.\n", detach ? "detached" : "attached", mode_str);
  return 0;
}

/**
* Detach the XDP program from the interface.
*
* @param ifidx Interface index.
* @param prog XDP program.
* @return 0 on success, -1 on failure.
*/
int detach_xdp(int ifidx, struct xdp_program *prog)
{
  int err;
  err = xdp_program__detach(prog, ifidx, 0, 0);

  if (err < 0)
  {
    fprintf(stderr, "ERROR: failed to detach program from interface: %s\n", strerror(-err));
    return -1;
  }

  return 0;
}