#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <xdp/prog_dispatcher.h>
#include <xdp/xdp_helpers.h>

#include "common.h"
#include "config.h"
#include "a2s_defs.h"

#include "utils/maps.h"
#include "utils/swap.h"
#include "utils/csum.h"
#include "utils/cookie.h"

struct
{
  __uint(priority, XDP_MULTIPROG_PRIORITY);
  __uint(XDP_MULTIPROG_ACTION, XDP_MULTIPROG_ENABLED);
} XDP_RUN_CONFIG(xdpa2scache_program);

SEC("xdpa2scache")
int xdpa2scache_program(struct xdp_md *ctx)
{
  // Initialize data
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Initialize and validate ethernet header
  struct ethhdr *eth = data;

  if (unlikely(eth + 1 > (struct ethhdr *)data_end))
  {
    return XDP_DROP;
  }

  // IPv4 check (skip if not IPv4)
  if (eth->h_proto != htons(ETH_P_IP))
  {
    return XDP_PASS;
  }

  // Initialize and validate IP header
  struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));

  if (unlikely(iph + 1 > (struct iphdr *)data_end))
  {
    return XDP_DROP;
  }

  // We want to process only UDP packets, so early return pass if it is not UDP protocol
  if (iph->protocol != IPPROTO_UDP)
  {
    return XDP_PASS;
  }

  // Initialize and validate UDP header
  struct udphdr *udph = (struct udphdr *)(data + sizeof(struct ethhdr) + (iph->ihl * 4));

  if (unlikely(udph + 1 > (struct udphdr *)data_end))
  {
    return XDP_DROP;
  }

  // Pointer to the start of the UDP payload
  void *payload = (void *)(udph + 1);

  // Check if there are at least 9 bytes available in the payload and that the first 4 bytes match the CONNECTIONLESS_HEADER
  if (payload + 9 <= data_end && *((__u32 *)payload) == CONNECTIONLESS_HEADER)
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
      #ifdef A2S_NON_STEAM_SUPPORT
      if (payload_len == 25)
      #else
      if (payload_len == 25 || payload_len == 29)
      #endif
      {
        // Lookup the A2S_INFO response in the map using the server key
        val = bpf_map_lookup_elem(&a2s_info, &key);

        // Determine if this is a challenge request based on payload length
        #ifndef A2S_NON_STEAM_SUPPORT
        is_challenge = (payload_len == 25);
        #endif

        // A2S Debug: Log info query details, payload length, value size, and whether it's a challenge
        #ifdef A2S_DEBUG
        bpf_printk("[A2S DEBUG] A2S_INFO: Payload Length: %u, Value Size: %u, Is Challenge: %s\n",
        payload_len, val ? val->size : 0, is_challenge ? "true" : "false");
        #endif
      }
      break;

      case A2S_PLAYER:
      case A2S_RULES:
      // If neither A2S_PLAYER_ENABLE nor A2S_RULES_ENABLE is defined, drop the packet
      #if !defined(A2S_PLAYER_ENABLE) && !defined(A2S_RULES_ENABLE)
      #ifdef A2S_DEBUG
      bpf_printk("[A2S DEBUG] Dropping A2S_%s packet, because A2S_%s_ENABLE is disabled.\n",
      (query_type == A2S_PLAYER) ? "PLAYER" : "RULES", (query_type == A2S_PLAYER) ? "PLAYER" : "RULES");
      #endif
      return XDP_DROP;
      #endif

      if (payload_len == 9)
      {
        // If both are enabled (A2S_PLAYER and A2S_RULES)
        // Lookup the A2S_PLAYER or A2S_RULES response in the map using the server key
        #if defined(A2S_PLAYER_ENABLE) && defined(A2S_RULES_ENABLE)
        val = (query_type == A2S_PLAYER) ? bpf_map_lookup_elem(&a2s_player, &key) : bpf_map_lookup_elem(&a2s_rules, &key);

        // If only A2S_PLAYER is enabled, drop A2S_RULES packets
        #elif defined(A2S_PLAYER_ENABLE)
        if (query_type == A2S_RULES)
        {
          #ifdef A2S_DEBUG
          bpf_printk("[A2S DEBUG] Dropping A2S_RULES packet, because A2S_RULES_ENABLE is disabled.\n");
          #endif
          return XDP_DROP;
        }
        val = bpf_map_lookup_elem(&a2s_player, &key);

        // If only A2S_RULES is enabled, drop A2S_PLAYER packets
        #elif defined(A2S_RULES_ENABLE)
        if (query_type == A2S_PLAYER)
        {
          #ifdef A2S_DEBUG
          bpf_printk("[A2S DEBUG] Dropping A2S_PLAYER packet, because A2S_PLAYER_ENABLE is disabled.\n");
          #endif
          return XDP_DROP;
        }
        val = bpf_map_lookup_elem(&a2s_rules, &key);
        #endif

        // Determine if this is a challenge request by checking 4 bytes (00000000/FFFFFFFF)
        #if defined A2S_NON_STEAM_SUPPORT || defined A2S_DUAL_CHALLENGE_SUPPORT
        is_challenge = (*(__u32 *)(payload + 5) == 0x00000000 || *(__u32 *)(payload + 5) == 0xFFFFFFFF);
        #else
        is_challenge = (*(__u32 *)(payload + 5) == 0x00000000);
        #endif

        // A2S Debug: Log player/rules query details, payload length, value size, and whether it's a challenge
        #ifdef A2S_DEBUG
        bpf_printk("[A2S DEBUG] A2S_%s: Payload Length: %u, Value Size: %u, Is Challenge: %s\n",
        (query_type == A2S_PLAYER) ? "PLAYER" : "RULES", payload_len, val ? val->size : 0, is_challenge ? "true" : "false");
        #endif
      }
      break;

      // Return XDP_PASS by default, since we need to allow some other things for certain games starting with the same payload!
      // You can DROP here if there is nothing expected than the above A2S queries
      default:
      // A2S Debug: Log unknown query type to easily understand what else is being used
      #ifdef A2S_DEBUG
      bpf_printk("[A2S DEBUG] Unknown Query Type: 0x%02x, passing packet.\n", query_type);
      #endif
      return XDP_PASS;
    }

    // If val is not found in the map, drop the packet
    if (!val)
    {
      // A2S Debug: Log that no matching response was found for this key
      #ifdef A2S_DEBUG
      bpf_printk("[A2S DEBUG] Value not found for key (IP: %pI4, Port: %d), dropping packet.\n", &key.ip, ntohs(key.port));
      #endif
      return XDP_DROP;
    }

    // A2S Debug: Log whether we are preparing a challenge or data response
    #ifdef A2S_DEBUG
    bpf_printk("[A2S DEBUG] Preparing %s response.\n", is_challenge ? "cookie (challenge)" : "data");
    #endif

    // Check if it is challenge
    if (is_challenge)
    {
      // Adjust packet tail to match the required payload length
      payload_len = (__s32)(data_end - payload);

      if (bpf_xdp_adjust_tail(ctx, 9 - payload_len) != 0)
      {
        // A2S Debug: Log a failure message when adjusting tail size fails
        #ifdef A2S_DEBUG
        bpf_printk("[A2S DEBUG] Failed to adjust tail size for challenge response. Response size: %d bytes, Payload length: %d bytes, Adjustment required: %d bytes, dropping packet.\n",
        9, payload_len, 9 - payload_len);
        #endif
        return XDP_DROP;
      }

      // Reinitialize pointers again because of the tail adjustment
      data = (void *)(long)ctx->data;
      data_end = (void *)(long)ctx->data_end;

      eth = data;
      if (unlikely(eth + 1 > (struct ethhdr *)data_end))
      {
        return XDP_DROP;
      }

      iph = (struct iphdr *)(data + sizeof(struct ethhdr));
      if (unlikely(iph + 1 > (struct iphdr *)data_end))
      {
        return XDP_DROP;
      }

      udph = (struct udphdr *)(data + sizeof(struct ethhdr) + (iph->ihl * 4));
      if (unlikely(udph + 1 > (struct udphdr *)data_end))
      {
        return XDP_DROP;
      }

      payload = (void *)(udph + 1);
      if (payload + 9 > data_end)
      {
        // A2S Debug: Log insufficient space for payload when writing 9 byte response
        #ifdef A2S_DEBUG
        bpf_printk("[A2S DEBUG] Insufficient space for 9 byte challenge payload (Available space: %ld bytes), dropping packet.\n", data_end - payload);
        #endif
        return XDP_DROP;
      }

      // Write the response to the packet payload and create a cookie (challenge) based on the IP and UDP header
      memcpy(payload, "\xFF\xFF\xFF\xFF\x41", 5);
      *(__u32 *)(payload + 5) = create_cookie(iph, udph);

      // A2S Debug: Log the crafted cookie (challenge) and the full 9 byte response
      // NOTE: Cookie (challenge) is in little endian
      #ifdef A2S_DEBUG
      bpf_printk("[A2S DEBUG] Crafted cookie (challenge) 0x%x\n", *(__u32 *)(payload + 5));

      // A2S Debug: Log source and destination IPs and ports for the A2S challenge packet that we are sending
      bpf_printk("[A2S DEBUG] Sending A2S Challenge: Source IP: %pI4, Source Port: %d, Destination IP: %pI4, Destination Port: %d\n",
      &iph->daddr, ntohs(udph->dest), &iph->saddr, ntohs(udph->source));
      #endif

      // Swap, calculate checksum, set TTL and reinitialize checksums for Ethernet, IP, and UDP headers
      swap_eth(eth);
      swap_ip(iph);
      swap_udp(udph);

      udph->len = htons(sizeof(struct udphdr) + 9);
      udph->check = 0;
      udph->check = calc_udp_csum(iph, udph, data_end);

      __u16 old_tot_len = iph->tot_len;
      __u8 old_ttl = iph->ttl;

      iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 9);
      iph->ttl = 64;

      iph->check = csum_diff4(old_tot_len, iph->tot_len, iph->check);
      iph->check = csum_diff4(old_ttl, iph->ttl, iph->check);

      return XDP_TX;
    }
    // Else if it is not challenge, proceed with data processing
    else
    {
      // Get the location of the cookie (challenge)
      #ifdef A2S_NON_STEAM_SUPPORT
      if (query_type != A2S_INFO)
      {
        __u32 *cookie = payload + 5;

        // Make sure we dont go out of range of the packet
        if (unlikely(cookie + 1 > data_end))
        {
          // A2S Debug: Log insufficient space for 4 byte cookie (challenge)
          #ifdef A2S_DEBUG
          bpf_printk("[A2S DEBUG] Insufficient space for 4 byte cookie (challenge) payload (Available space: %ld bytes), dropping packet.\n", data_end - payload);
          #endif
          return XDP_DROP;
        }

        // Cookie (challenge) check: If the cookie is not valid, we will drop the packet
        if (!check_cookie(iph, udph, *cookie))
        {
          // A2S Debug: Log that the cookie was invalid and that we are dropping the packet
          // NOTE: Cookie (challenge) is in little endian
          #ifdef A2S_DEBUG
          bpf_printk("[A2S DEBUG] Cookie (challenge) is invalid - 0x%x, dropping packet.\n", *cookie);
          #endif
          return XDP_DROP;
        }

        // A2S Debug: Log that the cookie (challenge) received is valid
        // NOTE: Cookie (challenge) is in little endian
        #ifdef A2S_DEBUG
        bpf_printk("[A2S DEBUG] Cookie (challenge) is valid - 0x%x, proceeding with next steps.\n", *cookie);
        #endif
      }
      #else
      __u32 *cookie = payload + (query_type == A2S_INFO ? 25 : 5);

      // Make sure we dont go out of range of the packet
      if (unlikely(cookie + 1 > data_end))
      {
        // A2S Debug: Log insufficient space for 4 byte cookie (challenge)
        #ifdef A2S_DEBUG
        bpf_printk("[A2S DEBUG] Insufficient space for 4 byte cookie (challenge) payload (Available space: %ld bytes), dropping packet.\n", data_end - payload);
        #endif
        return XDP_DROP;
      }

      // Cookie (challenge) check: If the cookie is not valid, we will drop the packet
      if (!check_cookie(iph, udph, *cookie))
      {
        // A2S Debug: Log that the cookie was invalid and that we are dropping the packet
        // NOTE: Cookie (challenge) is in little endian
        #ifdef A2S_DEBUG
        bpf_printk("[A2S DEBUG] Cookie (challenge) is invalid - 0x%x, dropping packet.\n", *cookie);
        #endif
        return XDP_DROP;
      }

      // A2S Debug: Log that the cookie (challenge) received is valid
      // NOTE: Cookie (challenge) is in little endian
      #ifdef A2S_DEBUG
      bpf_printk("[A2S DEBUG] Cookie (challenge) is valid - 0x%x, proceeding with next steps.\n", *cookie);
      #endif
      #endif

      // Adjust packet tail to match the required payload length
      payload_len = (__s32)(data_end - payload);

      if (bpf_xdp_adjust_tail(ctx, val->size - payload_len) != 0)
      {
        // A2S Debug: Log a failure message when adjusting tail size fails
        #ifdef A2S_DEBUG
        bpf_printk("[A2S DEBUG] Failed to adjust tail size for data response. Response size: %d bytes, Payload length: %d bytes, Adjustment required: %d bytes, dropping packet.\n",
        val->size, payload_len, val->size - payload_len);
        #endif
        return XDP_DROP;
      }

      // Reinitialize pointers again because of the tail adjustment
      data = (void *)(long)ctx->data;
      data_end = (void *)(long)ctx->data_end;

      eth = data;
      if (unlikely(eth + 1 > (struct ethhdr *)data_end))
      {
        return XDP_DROP;
      }

      iph = (struct iphdr *)(data + sizeof(struct ethhdr));
      if (unlikely(iph + 1 > (struct iphdr *)data_end))
      {
        return XDP_DROP;
      }

      udph = (struct udphdr *)(data + sizeof(struct ethhdr) + (iph->ihl * 4));
      if (unlikely(udph + 1 > (struct udphdr *)data_end))
      {
        return XDP_DROP;
      }

      payload = (void *)(udph + 1);
      if (unlikely(payload + 1 > data_end))
      {
        // A2S Debug: Log insufficient space for at least 1 byte of payload after tail adjustment
        #ifdef A2S_DEBUG
        bpf_printk("[A2S DEBUG] Payload invalid after tail adjustment (need at least 1 byte), dropping packet.\n");
        #endif
        return XDP_DROP;
      }

      // Write the data into the payload we will send
      // This is really ugly, but it is better from copying byte by byte for now
      // Currently sticking with 8, 4, 2, 1, because of Debian 12 (kernel 6.1),
      // in 2027 I will try to optimize this part more and drop Debian 12
      __u32 val_data_size = val->size < sizeof(val->data) ? val->size : sizeof(val->data);
      __u32 i = 0;

      // 1. 8 bytes copy
      for (; i + 8 <= val_data_size; i += 8)
      {
        if (payload + i + 8 > data_end)
        break;

        *(__u64 *)(payload + i) = *(__u64 *)(val->data + i);
      }

      // 4 bytes copy
      if (i + 4 <= val_data_size && payload + i + 4 <= data_end)
      {
        *(__u32 *)(payload + i) = *(__u32 *)(val->data + i);
        i += 4;
      }

      // 2 bytes copy
      if (i + 2 <= val_data_size && payload + i + 2 <= data_end)
      {
        *(__u16 *)(payload + i) = *(__u16 *)(val->data + i);
        i += 2;
      }

      // 1 byte copy
      if (i + 1 <= val_data_size && payload + i + 1 <= data_end)
      {
        ((__u8 *)payload)[i] = val->data[i];
      }

      // A2S Debug: Log the crafted payload size and packet source/destination information
      #ifdef A2S_DEBUG
      bpf_printk("[A2S DEBUG] Crafted %d bytes of data to send.\n", val_data_size);
      bpf_printk("[A2S DEBUG] Sending A2S Data: Source IP: %pI4, Source Port: %d, Destination IP: %pI4, Destination Port: %d\n",
      &iph->daddr, ntohs(udph->dest), &iph->saddr, ntohs(udph->source));
      #endif

      // Swap, calculate checksum, set TTL and reinitialize checksums for Ethernet, IP, and UDP headers
      swap_eth(eth);
      swap_ip(iph);
      swap_udp(udph);

      udph->len = htons(sizeof(struct udphdr) + val_data_size);
      udph->check = 0;
      udph->check = calc_udp_csum(iph, udph, data_end);

      __u16 old_tot_len = iph->tot_len;
      __u8 old_ttl = iph->ttl;

      iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + val_data_size);
      iph->ttl = 64;

      iph->check = csum_diff4(old_tot_len, iph->tot_len, iph->check);
      iph->check = csum_diff4(old_ttl, iph->ttl, iph->check);

      return XDP_TX;
    }
  }

  // Default: Pass the packet
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);