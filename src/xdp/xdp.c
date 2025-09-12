#include <stdint.h>
#include <stdbool.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "a2s_defs.h"

#include "utils/maps.h"
#include "utils/cookie.h"
#include "utils/swap.h"
#include "utils/csum.h"
#include "utils/a2s_xdp.h"

SEC("xdpa2scache")
int xdpa2scache_program(struct xdp_md *ctx)
{
  // Initialize data.
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Scan ethernet header
  struct ethhdr *eth = data;

  // Check if the ethernet header is valid
  if (unlikely(eth + 1 > (struct ethhdr *)data_end))
  {
    return XDP_DROP;
  }

  // IPv4 check (skip if not IPv4)
  if (eth->h_proto != htons(ETH_P_IP))
  {
    return XDP_PASS;
  }

  // Initialize IP header
  struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));

  // Validate IP header
  if (unlikely(iph + 1 > (struct iphdr *)data_end))
  {
    return XDP_DROP;
  }

  // We want to process only UDP packets, so early return pass if it is not UDP protocol
  if (iph->protocol != IPPROTO_UDP)
  {
    return XDP_PASS;
  }

  // Initialize UDP header
  struct udphdr *udph = (struct udphdr *)(data + sizeof(struct ethhdr) + (iph->ihl * 4));

  // Validate UDP header
  if (unlikely(udph + 1 > (struct udphdr *)data_end))
  {
    return XDP_DROP;
  }

  void *payload = (void *)(udph + 1);
  __u32 payload_u32 = *((__u32 *)payload);

  if (payload + 8 <= data_end && payload_u32 == 0xFFFFFFFF)
  {
    struct a2s_server_key key = {0};
    key.ip = iph->daddr;
    key.port = udph->dest;

    __u8 query_type = *((__u8 *)(payload + 4));
    __u16 payload_len = ntohs(udph->len) - sizeof(struct udphdr);

    struct a2s_val *val = NULL;
    bool is_challenge = false;

    switch (query_type)
    {
      case A2S_INFO:
      if (payload_len == 29 || payload_len == 25)
      {
        val = bpf_map_lookup_elem(&a2s_info, &key);
        is_challenge = (payload_len == 25);
      }
      break;

      case A2S_PLAYERS:
      case A2S_RULES:
      if (payload_len == 9)
      {
        val = (query_type == A2S_PLAYERS)
        ? bpf_map_lookup_elem(&a2s_players, &key)
        : bpf_map_lookup_elem(&a2s_rules, &key);

        // The Steam (?) and TF2 server browser seem to be sending 00000000 now for the challenge request instead of the previously used FFFFFFFF
        is_challenge = (payload_u32 + 5 == 0x00000000);
      }
      break;

      // Return XDP_PASS by default, since we need to allow some other things for certain games starting with the same payload!
      // You can DROP here if there is nothing expected than the above A2S queries, starting with the same payload (FF FF FF FF)
      default:
      return XDP_PASS;
    }

    // If val is not found - DROP
    if (!val)
    return XDP_DROP;

    return is_challenge ? send_a2s_challenge(ctx) : send_a2s_data(ctx, query_type, val);
  }

  // Default: Pass the packet
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";