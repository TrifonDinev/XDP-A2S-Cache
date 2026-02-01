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
#include "utils/swap.h"
#include "utils/csum.h"
#include "utils/cookie.h"

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
        #ifndef A2S_NON_STEAM_SUPPORT
        is_challenge = (payload_len == 25);
        #endif

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

        // Determine if this is a challenge request by checking 4 bytes (00000000) starting at the 6th byte of the payload
        #ifdef A2S_NON_STEAM_SUPPORT
        is_challenge = (*(__u32 *)(payload + 5) == 0x00000000 || *(__u32 *)(payload + 5) == 0xFFFFFFFF);
        #else
        is_challenge = (*(__u32 *)(payload + 5) == 0x00000000);
        #endif

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

    // Check if it is challenge
    if (is_challenge)
    {
      // Create a cookie (challenge) based on the IP and UDP header
      __u32 challenge = create_cookie(iph, udph);

      // Prepare the response to send back
      __u8 response[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0xFF, 0xFF, 0xFF};
      memcpy(response + 5, &challenge, 4);

      // Adjust the size of the payload when there is a difference
      if (bpf_xdp_adjust_tail(ctx, sizeof(response) - payload_len) != 0)
      {
        // A2S Debug: Log a failure message when adjusting tail size fails
        #ifdef A2S_DEBUG
        bpf_printk("A2S Challenge: Failed to adjust tail size for response. Response size: %d bytes, Payload length: %d bytes, Adjustment required: %d bytes, dropping packet.\n",
        sizeof(response), payload_len, sizeof(response) - payload_len);
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
        bpf_printk("A2S Challenge: Insufficient space for 9 byte payload (Available space: %ld bytes), dropping packet.\n", data_end - payload);
        #endif
        return XDP_DROP;
      }

      // Write the response to the packet payload
      memcpy(payload, response, sizeof(response));

      // A2S Debug: Log the crafted cookie (challenge) and the full 9 byte response
      // NOTE: Cookie (challenge) is in little endian
      #ifdef A2S_DEBUG
      bpf_printk("A2S Challenge: Crafted cookie (challenge) 0x%x, Full Response: 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x\n", 
      challenge, response[0], response[1], response[2], response[3], response[4], response[5], response[6], response[7], response[8]);

      // A2S Debug: Log source and destination IPs and ports for the A2S challenge packet that we are sending
      bpf_printk("Sending A2S Challenge: Source IP: %pI4, Source Port: %d, Destination IP: %pI4, Destination Port: %d\n",
      &iph->daddr, ntohs(udph->dest), &iph->saddr, ntohs(udph->source));
      #endif

      // Swap, calculate checksum, set TTL and reinitialize checksums for Ethernet, IP, and UDP headers
      swap_eth(eth);
      swap_ip(iph);
      swap_udp(udph);

      udph->len = htons(sizeof(struct udphdr) + 9);
      udph->check = 0;
      udph->check = calc_udp_csum(iph, udph, data_end);

      __u16 old_len = iph->tot_len;
      iph->tot_len = htons(data_end - data - sizeof(struct ethhdr));

      __u8 old_ttl = iph->ttl;
      iph->ttl = 64;

      iph->check = csum_diff4(old_len, iph->tot_len, iph->check);
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
          // A2S Debug: Log insufficient space for 1 byte cookie (challenge)
          #ifdef A2S_DEBUG
          bpf_printk("A2S Data: Insufficient space for 1 byte cookie (challenge) payload (Available space: %ld bytes), dropping packet.\n", data_end - payload);
          #endif
          return XDP_DROP;
        }

        // Cookie (challenge) check: If the cookie is not valid, we will drop the packet
        if (!check_cookie(iph, udph, *cookie))
        {
          // A2S Debug: Log that the cookie was invalid and that we are dropping the packet
          // NOTE: Cookie (challenge) is in little endian
          #ifdef A2S_DEBUG
          bpf_printk("A2S Data: Cookie (challenge) is invalid - 0x%x, dropping packet.\n", *cookie);
          #endif
          return XDP_DROP;
        }
      }
      #else
      __u32 *cookie = payload + (query_type == A2S_INFO ? 25 : 5);

      // Make sure we dont go out of range of the packet
      if (unlikely(cookie + 1 > data_end))
      {
        // A2S Debug: Log insufficient space for 1 byte cookie (challenge)
        #ifdef A2S_DEBUG
        bpf_printk("A2S Data: Insufficient space for 1 byte cookie (challenge) payload (Available space: %ld bytes), dropping packet.\n", data_end - payload);
        #endif
        return XDP_DROP;
      }

      // Cookie (challenge) check: If the cookie is not valid, we will drop the packet
      if (!check_cookie(iph, udph, *cookie))
      {
        // A2S Debug: Log that the cookie was invalid and that we are dropping the packet
        // NOTE: Cookie (challenge) is in little endian
        #ifdef A2S_DEBUG
        bpf_printk("A2S Data: Cookie (challenge) is invalid - 0x%x, dropping packet.\n", *cookie);
        #endif
        return XDP_DROP;
      }
      #endif

      // A2S Debug: Log that the cookie (challenge) received is valid
      // NOTE: Cookie (challenge) is in little endian
      #ifdef A2S_DEBUG
      bpf_printk("A2S Data: Cookie (challenge) is valid - 0x%x, proceeding with next steps.\n", *cookie);
      #endif

      // Resize packet to fit payload
      if (bpf_xdp_adjust_tail(ctx, val->size - payload_len) != 0)
      {
        // A2S Debug: Log a failure message when adjusting tail size fails
        #ifdef A2S_DEBUG
        bpf_printk("A2S Data: Failed to adjust tail size for response. Response size: %d bytes, Payload length: %d bytes, Adjustment required: %d bytes, dropping packet.\n",
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
        // A2S Debug: Log insufficient space for 1 byte payload after tail adjustment
        #ifdef A2S_DEBUG
        bpf_printk("A2S Data: Insufficient space for 1 byte payload (Available space: %ld bytes), dropping packet.\n", data_end - payload);
        #endif
        return XDP_DROP;
      }

      // Write the data into the payload we will send
      __u32 val_data_size = val->size < sizeof(val->data) ? val->size : sizeof(val->data);

      for (__u32 i = 0; i < val_data_size; i++)
      {
        if (payload + (i + 1) > data_end)
        {
          break;
        }

        ((__u8 *)payload)[i] = val->data[i];
      }

      // A2S Debug: Log the crafted payload size and packet source/destination information
      #ifdef A2S_DEBUG
      bpf_printk("A2S Data: Crafted %d bytes of data to send.\n", val_data_size);
      bpf_printk("Sending A2S Data: Source IP: %pI4, Source Port: %d, Destination IP: %pI4, Destination Port: %d\n",
      &iph->daddr, ntohs(udph->dest), &iph->saddr, ntohs(udph->source));
      #endif

      // Swap, calculate checksum, set TTL and reinitialize checksums for Ethernet, IP, and UDP headers
      swap_eth(eth);
      swap_ip(iph);
      swap_udp(udph);

      udph->len = htons(sizeof(struct udphdr) + val->size);
      udph->check = 0;
      udph->check = calc_udp_csum(iph, udph, data_end);

      __u16 old_len = iph->tot_len;
      iph->tot_len = htons(data_end - data - sizeof(struct ethhdr));

      __u8 old_ttl = iph->ttl;
      iph->ttl = 64;

      iph->check = csum_diff4(old_len, iph->tot_len, iph->check);
      iph->check = csum_diff4(old_ttl, iph->ttl, iph->check);

      return XDP_TX;
    }
  }

  // Default: Pass the packet
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";