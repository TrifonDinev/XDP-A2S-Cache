#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

#include "common.h"
#include "a2s_defs.h"
#include "helpers.h"

/**
* A2S_QUERY_TIME_SEC - Interval (in seconds) between A2S queries
*
* Determines how frequently the program polls for data updates from the server(s).
* A value in the 5-10 seconds range is reasonable for fresher data I think so.
*
* BEWARE: Long caching data may be flagged as spoofed by some master servers (e.g., Steam master server), as far as I know!
*/
#define A2S_QUERY_TIME_SEC 5

void *a2s_query_servers(void *arg)
{
  loader_ctx_t *ctx = (loader_ctx_t *)arg;

  const struct
  {
    const uint8_t request_data[32];
    const char *map_name;
    int map_fd;
    uint8_t req_size;
  } queries[] =
  {
    { "\xFF\xFF\xFF\xFF\x54Source Engine Query\x00", "A2S_INFO", ctx->xdp_maps.a2s_info, 25 },
    { "\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF", "A2S_PLAYERS", ctx->xdp_maps.a2s_players, 9 },
    { "\xFF\xFF\xFF\xFF\x56\xFF\xFF\xFF\xFF", "A2S_RULES", ctx->xdp_maps.a2s_rules, 9 }
  };

  enum
  {
    NUM_QUERIES = sizeof(queries) / sizeof(queries[0]),
    MAX_EVENTS = 64
  };

  typedef struct
  {
    struct a2s_val last_responses[NUM_QUERIES];
    struct sockaddr_in addr;
    unsigned char challenge_buf[32];
    int current_j;
    bool received_any;
    bool maps_cleaned_already;

    #ifdef A2S_DEBUG
    char ip_port[24];
    #endif
  } srv_state_t;

  int sockfd = -1, epfd = -1, tfd = -1;
  srv_state_t *states = NULL;
  unsigned char recv_buffer[A2S_MAX_SIZE];
  struct epoll_event events[MAX_EVENTS];

  states = calloc(ctx->server_count, sizeof(srv_state_t));
  if (!states)
  {
    perror("states calloc failed");
    goto cleanup;
  }

  if ((sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP)) < 0)
  {
    perror("Socket creation failed");
    goto cleanup;
  }

  // Bind socket to the interface we use to prevent routing via down links (e.g. secondary interface)
  if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ctx->ifname, strlen(ctx->ifname) + 1) < 0)
  {
    #ifdef A2S_DEBUG
    fprintf(stderr, "ERROR: Failed to bind socket to %s: %s\n", ctx->ifname, strerror(errno));
    #else
    perror("SO_BINDTODEVICE failed");
    #endif
  }

  // Increase buffer, just to be safe
  int rcvbuf = 8 * 1024 * 1024;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
  {
    perror("SO_RCVBUF failed");
  }

  if ((epfd = epoll_create1(EPOLL_CLOEXEC)) < 0
  || (tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC)) < 0)
  {
    perror(epfd < 0 ? "epoll_create1 failed" : "timerfd_create failed");
    goto cleanup;
  }

  struct itimerspec ts = {{A2S_QUERY_TIME_SEC, 0}, {0, 1}};
  if (timerfd_settime(tfd, 0, &ts, NULL) < 0)
  {
    perror("timerfd_settime failed");
    goto cleanup;
  }

  struct epoll_event ev = {0};
  ev.events = EPOLLIN;

  if ((ev.data.fd = tfd, epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev) < 0)
  || (ev.data.fd = sockfd, epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0))
  {
    perror(ev.data.fd == tfd ? "epoll_ctl tfd failed" : "epoll_ctl sockfd failed");
    goto cleanup;
  }

  for (int i = 0; i < ctx->server_count; i++)
  {
    srv_state_t *srv = &states[i];
    srv->addr = ctx->servers[i];

    // current_j tracks which query is being sent to the server
    // Initialized to -1 on start to indicate no query has been sent yet
    // When we first send a query, it will be set to 0
    srv->current_j = -1;

    // Prepare the data in challenge_buf array
    memcpy(srv->challenge_buf, queries[0].request_data, queries[0].req_size);

    #ifdef A2S_DEBUG
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srv->addr.sin_addr, ip_str, sizeof(ip_str));
    snprintf(srv->ip_port, sizeof(srv->ip_port), "%s:%u", ip_str, ntohs(srv->addr.sin_port));
    #endif
  }

  while (ctx->running)
  {
    int nfds = epoll_wait(epfd, events, MAX_EVENTS, 1000);

    if (nfds < 0 && errno != EINTR)
    {
      perror("epoll_wait failed");
      break;
    }

    for (int i = 0; i < nfds && ctx->running; i++)
    {
      if (events[i].data.fd == tfd)
      {
        uint64_t exp;

        if (read(tfd, &exp, sizeof(exp)) < 0)
        {
          if (errno != EAGAIN && errno != EWOULDBLOCK)
          {
            perror("[TFD] timerfd read failed");
          }
          continue;
        }

        // Loop over all servers to send queries or handle timeouts
        for (int s = 0; s < ctx->server_count; s++)
        {
          srv_state_t *srv = &states[s];

          // If server never responded to the first query (A2S_INFO), then by logic it is timed out
          if (!srv->received_any && srv->current_j == 0)
          {
            #ifdef A2S_DEBUG
            printf("[A2S] Server %s timed out on %s. Skipping other queries.\n", srv->ip_port, queries[srv->current_j].map_name);
            #endif

            // If maps are not cleaned already we clean
            if (!srv->maps_cleaned_already)
            {
              // Initialize server key and store server IP and port
              struct a2s_server_key xdp_key = {0};
              xdp_key.ip = srv->addr.sin_addr.s_addr;
              xdp_key.port = srv->addr.sin_port;

              for (size_t k = 0; k < NUM_QUERIES; k++)
              {
                bpf_map_delete_elem(queries[k].map_fd, &xdp_key);
                srv->last_responses[k].size = 0;
              }

              // Set maps as cleaned
              srv->maps_cleaned_already = true;

              #ifdef A2S_DEBUG
              printf("[A2S] BPF maps purged for %s due to timeout (performing once).\n", srv->ip_port);
              #endif
            }
          }

          // Set things to default
          srv->current_j = 0;
          srv->received_any = false;

          // Send first query (A2S_INFO)
          ssize_t sent = sendto(sockfd, queries[srv->current_j].request_data, queries[srv->current_j].req_size,
            MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&srv->addr, sizeof(struct sockaddr_in));

          if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
          {
            #ifdef A2S_DEBUG
            fprintf(stderr, "[A2S] sendto failed for %s (%s): %s\n",
            srv->ip_port, queries[srv->current_j].map_name, strerror(errno));
            #else
            perror("[A2S] sendto failed");
            #endif
          }
        }
      }
      else if (events[i].data.fd == sockfd)
      {
        struct sockaddr_in src_addr;
        socklen_t addrlen = sizeof(src_addr);
        ssize_t n = recvfrom(sockfd, recv_buffer, A2S_MAX_SIZE, MSG_DONTWAIT, (struct sockaddr *)&src_addr, &addrlen);

        if (n <= 0)
        {
          if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
          {
            perror("[SOCKFD] recvfrom failed");
          }
          continue;
        }

        // Find which server this incoming packet belongs to (match by Port and IP)
        srv_state_t *srv = NULL;

        for (int s = 0; s < ctx->server_count; s++)
        {
          if (states[s].addr.sin_port == src_addr.sin_port && states[s].addr.sin_addr.s_addr == src_addr.sin_addr.s_addr)
          {
            srv = &states[s];
            break;
          }
        }

        // Ignore invalid packets
        if (!srv || n < 5 || n > A2S_MAX_SIZE || *(uint32_t *)recv_buffer != 0xFFFFFFFF)
        {
          #ifdef A2S_DEBUG
          if (!srv)
          {
            printf("[A2S] Unknown source packet received\n");
          }
          else if (n < 5 || n > A2S_MAX_SIZE)
          {
            printf("[A2S] %s from %s (%s): Value size: %zd\n", n < 5 ? "Invalid/Short A2S packet" : "A2S packet is above A2S_MAX_SIZE",
            srv->ip_port, queries[srv->current_j].map_name, n);
          }
          else if (recv_buffer[0] == 0xFE)
          {
            printf("[A2S] Multi Packet/Split Packet from %s (%s). Skipping as we do not support this.\n",
            srv->ip_port, queries[srv->current_j].map_name);
          }
          else
          {
            printf("[A2S] Invalid A2S packet from %s (%s): Value size: %zd\n", srv->ip_port, queries[srv->current_j].map_name, n);
          }
          #endif
          continue;
        }

        uint8_t header = recv_buffer[4];
        int step = -1;

        // Determine which query type this response belongs to
        switch (header)
        {
          case A2S_CHALLENGE: step = srv->current_j; break;
          case 0x49: step = 0; break;
          case 0x44: step = 1; break;
          case 0x45: step = 2; break;

          default:
          #ifdef A2S_DEBUG
          printf("[A2S] Unknown header 0x%02X from %s\n", header, srv->ip_port);
          #endif
          continue;
        }

        // Ignore out of order packets
        if (step < 0 || step >= NUM_QUERIES || step != srv->current_j)
        {
          #ifdef A2S_DEBUG
          if (step < 0 || step >= NUM_QUERIES)
          {
            printf("[A2S] Invalid step %d for header 0x%02X from %s\n", step, header, srv->ip_port);
          }
          else
          {
            printf("[A2S] Ignoring out of order packet from %s (got %d, expected %d)\n", srv->ip_port, step, srv->current_j);
          }
          #endif
          continue;
        }

        // Set that we received anything and maps are not cleaned
        srv->received_any = true;
        srv->maps_cleaned_already = false;

        // Handle challenge if present
        if (header == A2S_CHALLENGE)
        {
          if (n != 9)
          {
            #ifdef A2S_DEBUG
            printf("[A2S] Invalid challenge size from %s: Value size: %zd (expected 9)\n", srv->ip_port, n);
            #endif
            continue;
          }

          #ifdef A2S_DEBUG
          printf("[A2S] Received challenge response from %s (%s) | Hex: %02X %02X %02X %02X\n",
          srv->ip_port, queries[step].map_name, recv_buffer[5], recv_buffer[6], recv_buffer[7], recv_buffer[8]);
          #endif

          // Prepare and send challenge response to server
          int offset = (queries[step].request_data[4] == A2S_INFO) ? 25 : 5;

          if (offset == 5)
          {
            srv->challenge_buf[4] = queries[step].request_data[4];
          }

          // Copy challenge token from received packet into buffer
          memcpy(srv->challenge_buf + offset, recv_buffer + 5, 4);

          // Send the challenge response back to the server
          ssize_t sent = sendto(sockfd, srv->challenge_buf, offset + 4,
            MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&srv->addr, sizeof(struct sockaddr_in));

          if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
          {
            #ifdef A2S_DEBUG
            fprintf(stderr, "[A2S] challenge sendto failed for %s (%s): %s\n",
            srv->ip_port, queries[step].map_name, strerror(errno));
            #else
            perror("[A2S] challenge sendto failed");
            #endif
          }
          #ifdef A2S_DEBUG
          else
          {
            printf("[A2S] Sent Challenge response to %s (%s)\n", srv->ip_port, queries[step].map_name);
          }
          #endif
          continue;
        }
        // If it is not challenge, continue handling the response
        else
        {
          // Check if there is data change:
          // INFO: Small, full compare (n) should be fast enough
          // PLAYERS: Compare the first 60 bytes. This covers the player count and the first player's score/time, which is enough to trigger update
          // RULES: Dynamic CVARs like e.g., mp_timeleft, which can point to a data change can be deep (600+ bytes), so we must perform a full compare (n)
          if (n == srv->last_responses[step].size && memcmp(srv->last_responses[step].data, recv_buffer, step == 1 && n > 60 ? 60 : n) == 0)
          {
            #ifdef A2S_DEBUG
            printf("[A2S] No data change for %s (%s). Skipping BPF update.\n", srv->ip_port, queries[step].map_name);
            #endif
          }
          else
          {
            // Initialize server key and store server IP and port
            struct a2s_server_key xdp_key = {0};
            xdp_key.ip = src_addr.sin_addr.s_addr;
            xdp_key.port = src_addr.sin_port;

            srv->last_responses[step].size = n;
            memcpy(srv->last_responses[step].data, recv_buffer, n);

            if (bpf_map_update_elem(queries[step].map_fd, &xdp_key, &srv->last_responses[step], BPF_ANY) < 0)
            {
              #ifdef A2S_DEBUG
              fprintf(stderr, "[A2S] BPF map update failed for %s (%s): %s\n", srv->ip_port, queries[step].map_name, strerror(errno));
              #endif
            }
            #ifdef A2S_DEBUG
            else
            {
              printf("[A2S] Map Updated: %s | Server: %s | Size: %zd\n", queries[step].map_name, srv->ip_port, n);
            }
            #endif
          }

          // Continue to next query
          if (++srv->current_j < NUM_QUERIES)
          {
            // Send next A2S query to the server in the sequence
            ssize_t sent = sendto(sockfd, queries[srv->current_j].request_data, queries[srv->current_j].req_size,
              MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&srv->addr, sizeof(struct sockaddr_in));

            if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            {
              #ifdef A2S_DEBUG
              fprintf(stderr, "[A2S] next query sendto failed for %s (%s): %s\n",
              srv->ip_port, queries[srv->current_j].map_name, strerror(errno));
              #else
              perror("[A2S] next query sendto failed");
              #endif
            }
          }
        }
      }
    }
  }

cleanup:
  if (tfd >= 0) close(tfd);
  if (epfd >= 0) close(epfd);
  if (sockfd >= 0) close(sockfd);

  free(states);
  printf("Background query thread resources released.\n");

  if (ctx->running) termination_handler(ctx, 0);
  return NULL;
}