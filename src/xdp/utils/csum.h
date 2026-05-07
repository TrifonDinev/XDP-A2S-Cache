#pragma once

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
* With some edit from me - Trifon Dinev - https://github.com/TrifonDinev/XDP-A2S-Cache , https://trifondinev.com
*
* @return 16-bit UDP checksum.
**/
#ifndef USE_HW_UDP_CSUM_OFFLOAD
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

  /* Mask 0x07FF (2047) bounds the scalar range to avoid verifier 1M instruction explosion.
   * Observed with VirtIO drivers and may also occur on other virtualized drivers/VMs.
   * Ensures correct behavior for small packets on VMware "vmxnet3" and physical NICs.
   * Tested on: I350, X550, X710, E810, KVM/QEMU VirtIO, VMware vmxnet3.
   * NOTE: Adjust the 0x07FF mask and the 1480 cap if jumbo frames are used.
  */
  __u16 udp_len = ntohs(udph->len) & 0x07FF;

  // Cap length at 1480 bytes to ensure compliance with standard Ethernet MTU
  if (udp_len > 1480)
  {
    udp_len = 1480;
  }

  // Compute checksum on UDP header + payload
  for (int i = 0; i < udp_len; i += 2)
  {
    if ((void *)(buf + 1) > data_end)
    break;

    // Verifier safety check for kernels < 6.8
    if ((void *)buf <= data_end)
    {
      csum_buffer += *buf;
      buf++;
    }
  }

  // Handle the last byte if payload length is not 2-byte aligned
  if ((void *)buf + 1 <= data_end)
  {
    csum_buffer += *(__u8 *)buf;
  }

  return ~((__u16)csum_buffer + (__u16)(csum_buffer >> 16));
}
#endif