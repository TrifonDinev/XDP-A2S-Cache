#pragma once

/**
* Swaps ethernet header's source and destination MAC addresses.
*
* @param eth Pointer to Ethernet header.
*
* @return Void
**/
static __always_inline void swap_eth(struct ethhdr *eth)
{
  __u8 tmp[ETH_ALEN];
  memcpy(tmp, &eth->h_source, ETH_ALEN);

  memcpy(&eth->h_source, &eth->h_dest, ETH_ALEN);
  memcpy(&eth->h_dest, tmp, ETH_ALEN);
}

/**
* Swaps IPv4 header's source and destination IP addresses.
*
* @param iph Pointer to IPv4 header.
*
* @return Void
**/
static __always_inline void swap_ip(struct iphdr *iph)
{
  __be32 tmp;
  memcpy(&tmp, &iph->saddr, sizeof(__be32));

  memcpy(&iph->saddr, &iph->daddr, sizeof(__be32));
  memcpy(&iph->daddr, &tmp, sizeof(__be32));
}

/**
* Swaps UDP header's source and destination ports.
*
* @param udph Pointer to UDP header.
*
* @return Void
**/
static __always_inline void swap_udp(struct udphdr *udph)
{
  __be16 tmp;
  memcpy(&tmp, &udph->source, sizeof(__be16));

  memcpy(&udph->source, &udph->dest, sizeof(__be16));
  memcpy(&udph->dest, &tmp, sizeof(__be16));
}