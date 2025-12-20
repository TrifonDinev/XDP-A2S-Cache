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
  // Initialize data
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

  // Pointer to the start of the UDP payload
  void *payload = (void *)(udph + 1);

  // Check if there are at least 9 bytes available in the payload and that the first 4 bytes match 0xFFFFFFFF
  if (payload + 9 <= data_end && *((__u32 *)payload) == 0xFFFFFFFF)
  {
    // Initialize a key struct to identify the server (IP and port) for A2S lookups
    struct a2s_server_key key = {0};

    // Store the destination IP and port from the packet as a key for lookup
    key.ip = iph->daddr;
    key.port = udph->dest;

    // Read the query type from the 5th byte of the payload
    __u8 query_type = *((__u8 *)(payload + 4));

    // Calculate UDP payload length
    __u16 payload_len = ntohs(udph->len) - sizeof(struct udphdr);

    // Pointer to hold the A2S response data retrieved from maps
    struct a2s_val *val = NULL;

    // Boolean to indicate whether the incoming A2S query is a challenge request
    bool is_challenge = false;

    switch (query_type)
    {
      case A2S_INFO:
      if (payload_len == 25 || payload_len == 29)
      {
        // Lookup the A2S_INFO response in the map using the server key
        val = bpf_map_lookup_elem(&a2s_info, &key);

        // Determine if this is a challenge request based on payload length
        is_challenge = (payload_len == 25);

        // A2S Debug: Log info query details, payload length, value size, and whether it's a challenge
        #ifdef A2S_DEBUG
        bpf_printk("A2S Debug: A2S_INFO: Payload Length: %u, Value Size: %u, Is Challenge: %s\n",
        payload_len, val ? val->size : 0, is_challenge ? "true" : "false");
        #endif
      }
      break;

      case A2S_PLAYERS:
      case A2S_RULES:
      if (payload_len == 9)
      {
        // Lookup the A2S_PLAYERS or A2S_RULES response in the map using the server key
        val = (query_type == A2S_PLAYERS)
        ? bpf_map_lookup_elem(&a2s_players, &key)
        : bpf_map_lookup_elem(&a2s_rules, &key);

        // Determine if this is a challenge request based on payload length
        is_challenge = (*(__u32 *)(payload + 5) == 0x00000000);

        // A2S Debug: Log players/rules query details, payload length, value size, and whether it's a challenge
        #ifdef A2S_DEBUG
        bpf_printk("A2S Debug: A2S_%s: Payload Length: %u, Value Size: %u, Is Challenge: %s\n",
        (query_type == A2S_PLAYERS) ? "PLAYERS" : "RULES", payload_len, val ? val->size : 0, is_challenge ? "true" : "false");
        #endif
      }
      break;

      // Return XDP_PASS by default, since we need to allow some other things for certain games starting with the same payload!
      // You can DROP here if there is nothing expected than the above A2S queries, starting with the same payload (FF FF FF FF)
      default:
      // A2S Debug: Log unknown query type, so you can understand more easily what else is being used
      #ifdef A2S_DEBUG
      bpf_printk("A2S Debug: Unknown Query Type: 0x%02x, passing packet.\n", query_type);
      #endif
      return XDP_PASS;
    }

    // If val is not found in the map, drop the packet
    if (!val)
    {
      // A2S Debug: Log that no matching response was found for this key
      #ifdef A2S_DEBUG
      bpf_printk("A2S Debug: Value not found for key (IP: %pI4, Port: %d), dropping packet.\n", &key.ip, ntohs(key.port));
      #endif
      return XDP_DROP;
    }

    // A2S Debug: Log whether we are preparing a challenge or data response
    #ifdef A2S_DEBUG
    bpf_printk("A2S Debug: Preparing %s response.\n", is_challenge ? "cookie (challenge)" : "data");
    #endif
    return is_challenge ? send_a2s_challenge(ctx) : send_a2s_data(ctx, query_type, val);
  }

  // Default: Pass the packet
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";