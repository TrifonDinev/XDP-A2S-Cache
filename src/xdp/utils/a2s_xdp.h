#pragma once

static __always_inline int send_a2s_challenge(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Scan Ethernet header
  struct ethhdr *eth = data;
  if (unlikely(eth + 1 > (struct ethhdr *)data_end))
  {
    return XDP_DROP;
  }

  // Initialize IP header
  struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
  if (unlikely(iph + 1 > (struct iphdr *)data_end))
  {
    return XDP_DROP;
  }

  // Initialize UDP header
  struct udphdr *udph = (struct udphdr *)(data + sizeof(struct ethhdr) + (iph->ihl * 4));
  if (unlikely(udph + 1 > (struct udphdr *)data_end))
  {
    return XDP_DROP;
  }

  // Create a cookie (challenge) based on the IP and UDP header
  __u32 challenge = create_cookie(iph, udph);

  // Prepare the response to send back
  __u8 response[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0xFF, 0xFF, 0xFF};
  memcpy(response + 5, &challenge, 4);

  __u16 payload_len = ntohs(udph->len) - sizeof(struct udphdr);

  // Adjust the size of the payload when there is a difference
  if (bpf_xdp_adjust_tail(ctx, sizeof(response) - payload_len) != 0)
  {
    return XDP_DROP;
  }

  // Reinitialize pointers again because of the tail adjustment
  data_end = (void *)(long)ctx->data_end;
  data = (void *)(long)ctx->data;

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

  void* payload = (void *)udph + sizeof(struct udphdr);
  if (payload + 9 > data_end)
  {
    return XDP_DROP;
  }

  // Write the response to the packet payload
  memcpy(payload, response, sizeof(response));

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

static __always_inline int send_a2s_data(struct xdp_md *ctx, __u8 query_type, struct a2s_val *val)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Scan Ethernet header
  struct ethhdr *eth = data;
  if (unlikely(eth + 1 > (struct ethhdr *)data_end))
  {
    return XDP_DROP;
  }

  // Initialize IP header
  struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
  if (unlikely(iph + 1 > (struct iphdr *)data_end))
  {
    return XDP_DROP;
  }

  // Initialize UDP header
  struct udphdr *udph = (struct udphdr *)(data + sizeof(struct ethhdr) + (iph->ihl * 4));
  if (unlikely(udph + 1 > (struct udphdr *)data_end))
  {
    return XDP_DROP;
  }

  // Get out payload pointer
  void* payload = (void *)udph + sizeof(struct udphdr);
  __u16 payload_len = ntohs(udph->len) - sizeof(struct udphdr);

  // Get the location of the cookie (challenge)
  __u32 *cookie = payload + (query_type == A2S_INFO ? 25 : 5);

  // Make sure we dont go out of range of the packet
  if (unlikely(cookie + 1 > (void *)data_end))
  {
    return XDP_DROP;
  }

  // Validate cookie
  if (check_cookie(iph, udph, *cookie))
  {
    // Resize packet to fit payload
    if (bpf_xdp_adjust_tail(ctx, val->size - payload_len) != 0)
    {
      return XDP_DROP;
    }

    // Reinitialize pointers again because of the tail adjustment
    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

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

    payload = (void *)udph + sizeof(struct udphdr);
    if (unlikely(payload + 1 > (void *)data_end))
    {
      return XDP_DROP;
    }

    // Write the data into the payload we will send
    __u32 val_data_size = val->size < sizeof(val->data) ? val->size : sizeof(val->data);
    __u8 *payload_ptr = (void *)payload;
    __u8 *payload_end = (__u8 *)data_end;

    for (int i = 0; i < val_data_size; i++)
    {
      if (payload_ptr + (i + 1) > payload_end)
      {
        break;
      }

      payload_ptr[i] = val->data[i];
    }

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
  // If the cookie is not valid, we'll resend challenge for now
  // I think that it is better to create a map for the sended challenges per src ip/client, so we don't resend one after another endlessly
  else
  {
    return send_a2s_challenge(ctx);
  }
}