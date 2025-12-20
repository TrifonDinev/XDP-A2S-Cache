#pragma once

static __always_inline int send_a2s_challenge(struct xdp_md *ctx)
{
  // Initialize data
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

  // Calculate UDP payload length
  __u16 payload_len = ntohs(udph->len) - sizeof(struct udphdr);

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

  void* payload = (void *)udph + sizeof(struct udphdr);
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

static __always_inline int send_a2s_data(struct xdp_md *ctx, __u8 query_type, struct a2s_val *val)
{
  // Initialize data
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

  // Get the location of the cookie (challenge)
  __u32 *cookie = payload + (query_type == A2S_INFO ? 25 : 5);

  // Make sure we dont go out of range of the packet
  if (unlikely(cookie + 1 > (void *)data_end))
  {
    // A2S Debug: Log insufficient space for 1 byte cookie (challenge)
    #ifdef A2S_DEBUG
    bpf_printk("A2S Data: Insufficient space for 1 byte cookie (challenge) payload (Available space: %ld bytes), dropping packet.\n", data_end - payload);
    #endif
    return XDP_DROP;
  }

  // Validate cookie
  if (check_cookie(iph, udph, *cookie))
  {
    // A2S Debug: Log that the cookie (challenge) received is valid
    // NOTE: Cookie (challenge) is in little endian
    #ifdef A2S_DEBUG
    bpf_printk("A2S Data: Cookie (challenge) is valid - 0x%x, proceeding with next steps.\n", *cookie);
    #endif

    // Calculate UDP payload length
    __u16 payload_len = ntohs(udph->len) - sizeof(struct udphdr);

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

    payload = (void *)udph + sizeof(struct udphdr);
    if (unlikely(payload + 1 > (void *)data_end))
    {
      // A2S Debug: Log insufficient space for 1 byte payload after tail adjustment
      #ifdef A2S_DEBUG
      bpf_printk("A2S Data: Insufficient space for 1 byte payload (Available space: %ld bytes), dropping packet.\n", data_end - payload);
      #endif
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
  // If the cookie is not valid, we'll resend challenge for now
  else
  {
    // A2S Debug: Log that the cookie was invalid and that we are resending the challenge
    #ifdef A2S_DEBUG
    bpf_printk("A2S Data: Invalid cookie (challenge), Resending challenge.\n");
    #endif
    return send_a2s_challenge(ctx);
  }
}