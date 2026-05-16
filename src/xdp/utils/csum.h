#pragma once

/**
* Calculates the new checksum after changing a single 4-byte value.
*
* @param old_value The original 4-byte value.
* @param new_value The new 4-byte value to replace the old one.
* @param old_checksum The original checksum.
*
* @return The updated 16-bit checksum.
*/
static __always_inline __u16 csum_diff4(__u32 old_value, __u32 new_value, __u16 old_checksum)
{
  // Initialize sum with the complement of the old checksum, only considering the lower 16 bits.
  __u32 sum = ~old_checksum & 0xFFFF;

  // Add the complement of the lower 16 bits of the old value to the sum.
  sum += ~old_value & 0xFFFF;

  // Add the upper 16 bits of the old value to the sum.
  sum += old_value >> 16;

  // Add the lower 16 bits of the new value to the sum.
  sum += new_value & 0xFFFF;

  // Add the upper 16 bits of the new value to the sum.
  sum += new_value >> 16;

  // Fold 32-bit sum to 16 bits and add carry (RFC 1071)
  sum = (sum & 0xFFFF) + (sum >> 16);

  // (__u16) keeps the low 16 bits after the final fold
  return (__u16)~(sum + (sum >> 16));
}

/**
* Calculates the entire UDP checksum (including payload data) from scratch.
*
* @param iph Pointer to IPv4 header.
* @param udph Pointer to UDP header.
* @param data_end Pointer to packet's data end.
*
* @note All credit goes to FedeParola from https://github.com/iovisor/bcc/issues/2463#issuecomment-718800510
* With some edit from me - Trifon Dinev - https://trifondinev.com - https://github.com/TrifonDinev/XDP-A2S-Cache
*
* @return 16-bit UDP checksum.
*/
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

  // Compute checksum on UDP header + payload
  // 1480 is the max UDP size for a 1500 MTU
  for (int i = 0; i < 1480; i += 4)
  {
    if ((void *)(buf + 2) > data_end)
    break;

    __u32 val = *(__u32 *)buf;

    csum_buffer += (val & 0xFFFF);
    csum_buffer += (val >> 16);
    buf += 2;
  }

  // 2. Handle 2 bytes
  if ((void *)(buf + 1) <= data_end)
  {
    csum_buffer += *buf;
    buf++;
  }

  // 3. Handle the last byte
  if ((void *)buf + 1 <= data_end)
  {
    csum_buffer += *(__u8 *)buf;
  }

  // Fold 32-bit sum to 16 bits and add carry (RFC 1071)
  csum_buffer = (csum_buffer & 0xFFFF) + (csum_buffer >> 16);

  // (__u16) keeps the low 16 bits
  // Return 0xFFFF if the UDP checksum becomes 0x0000 (RFC 768)
  return ((__u16)~(csum_buffer + (csum_buffer >> 16))) ?: 0xFFFF;
}