#pragma once

#define MAX_UDP_SIZE 1480

/**
* Calculates the new checksum after changing a single 4-byte value.
*
* @param old_value The original 4-byte value.
* @param new_value The new 4-byte value to replace the old one.
* @param old_checksum The original checksum.
*
* @return The updated 16-bit checksum.
**/
static __always_inline uint16_t csum_diff4(uint32_t old_value, uint32_t new_value, uint16_t old_checksum) 
{
  // Initialize sum with the complement of the old checksum, only considering the lower 16 bits.
  uint32_t sum = ~old_checksum & 0xFFFF;

  // Add the complement of the lower 16 bits of the old value to the sum.
  sum += ~old_value & 0xFFFF;

  // Add the upper 16 bits of the old value to the sum.
  sum += (old_value >> 16);

  // Add the lower 16 bits of the new value to the sum.
  sum += new_value & 0xFFFF;

  // Add the upper 16 bits of the new value to the sum.
  sum += new_value >> 16;

  // Combine the lower and upper parts of the sum and keep only the lower 16 bits.
  // This step handles any overflow by adding it back into the sum.
  sum = (sum & 0xFFFF) + (sum >> 16);

  // Return the complement of the sum
  return (uint16_t)~sum;
}

/**
* Calculates the entire UDP checksum (including payload data) from scratch.
*
* @param iph Pointer to IPv4 header.
* @param udph Pointer to UDP header.
* @param data_end Pointer to packet's data end.
*
* @note All credit goes to FedeParola from https://github.com/iovisor/bcc/issues/2463
*
* @return 16-bit UDP checksum.
**/
static __always_inline __u16 calc_udp_csum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
  __u32 csum_buffer = 0;
  __u16 *buf = (void *)udph;

  // Compute pseudo-header checksum
  csum_buffer += (__u16)iph->saddr;
  csum_buffer += (__u16)(iph->saddr >> 16);
  csum_buffer += (__u16)iph->daddr;
  csum_buffer += (__u16)(iph->daddr >> 16);
  csum_buffer += (__u16)iph->protocol << 8;
  csum_buffer += udph->len;

  // Compute checksum on udp header + payload
  for (int i = 0; i < MAX_UDP_SIZE; i += 2)
  {
    if ((void *)(buf + 1) > data_end)
    {
      break;
    }

    if ((void *)buf <= data_end)
    {
      csum_buffer += *buf;
      buf++;
    }
  }

  if ((void *)buf + 1 <= data_end)
  {
    // In case payload is not 2 bytes aligned
    csum_buffer += *(__u8 *)buf;
  }

  __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
  csum = ~csum;

  return csum;
}