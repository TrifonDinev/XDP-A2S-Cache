#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>

#include "common.h"
#include "a2s_defs.h"
#include "a2s_query_servers.h"

/**
* A2S_QUERY_TIME_SEC - Interval (in seconds) between A2S queries.
* Determines how frequently the program polls servers for updates.
* A value in the 5–10 seconds range is reasonable for fresher data I think so.
* BEWARE of long caching data, some master servers (steam master server?) may flag it as spoofed as far as I know!
*/
#define A2S_QUERY_TIME_SEC 5

void *a2s_query_servers(void *args)
{
  thread_args_t *ctx = (thread_args_t *)args;
  xdp_maps_t *xdp_maps = ctx->xdp_maps;
  struct server_config *config = ctx->config;
  udp_client_t client;

  // Query types and corresponding request data
  struct
  {
    int query_type;
    const char *request_data;
    size_t req_size;
  } query_types[] =
  {
    {A2S_INFO, "\xFF\xFF\xFF\xFF\x54Source Engine Query\x00", 25},
    {A2S_PLAYERS, "\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF", 9},
    {A2S_RULES, "\xFF\xFF\xFF\xFF\x56\xFF\xFF\xFF\xFF", 9}
  };

  while (1)
  {
    for (int i = 0; i < config->server_count; i++)
    {
      // Skip servers with an invalid (NULL) IP address
      if (config->servers[i].ip == NULL) continue;

      // Prepare socket only once for the server
      if (socket_client_prepare(&client, config->servers[i].ip, config->servers[i].port) < 0)
      {
        #ifdef A2S_DEBUG
        printf("Failed to prepare socket for %s:%d\n", config->servers[i].ip, config->servers[i].port);
        #endif
        continue;
      }

      // Query each server for different types of information
      for (int j = 0; j < sizeof(query_types) / sizeof(query_types[0]); j++)
      {
        const char *request_data = query_types[j].request_data;
        size_t req_size = query_types[j].req_size;

        // Send the query request
        if (socket_client_send(&client, request_data, req_size) != req_size)
        {
          #ifdef A2S_DEBUG
          printf("Error sending request for query type %d\n", query_types[j].query_type);
          #endif
          continue;
        }

        // Receive the response
        char buffer[A2S_MAX_SIZE];
        int n = socket_client_recv(&client, buffer, A2S_MAX_SIZE);

        // Initialize server key and query response structures to zero
        struct a2s_server_key xdp_key = {0};
        struct a2s_val val = {0};

        // Store server IP and port from client address
        xdp_key.ip = client.addr.sin_addr.s_addr;
        xdp_key.port = client.addr.sin_port;

        if (n <= 0)
        {
          #ifdef A2S_DEBUG
          printf("Timeout or error occurred while receiving response for query type %d\n", query_types[j].query_type);
          #endif

          // Remove server from map if not responsive. By logic, if server is not responsive, it can be "Offline".
          int maps[] = { xdp_maps->a2s_info, xdp_maps->a2s_players, xdp_maps->a2s_rules };

          #ifdef A2S_DEBUG
          const char *map_names[] = { "a2s_info", "a2s_players", "a2s_rules" };
          #endif

          for (int i = 0; i < sizeof(maps) / sizeof(maps[0]); i++)
          {
            // Delete the element from the map if it exists
            if (bpf_map_lookup_elem(maps[i], &xdp_key, &val) == 0)
            {
              #ifdef A2S_DEBUG
              // Print which map and key is being deleted
              printf("Deleting unresponsive server from map: %s\n", map_names[i]);
              printf("Key: IP = 0x%X, Port = %d\n", xdp_key.ip, ntohs(xdp_key.port));
              #endif

              // Delete the element from the map
              bpf_map_delete_elem(maps[i], &xdp_key);
            }
          }
          continue;
        }

        // Null-terminate the received data for safety
        buffer[n] = '\0';

        // Handle challenge if present
        if (buffer[4] == A2S_CHALLENGE)
        {
          int challenge_number = *(int *)(buffer + 5);

          #ifdef A2S_DEBUG
          printf("Challenge detected, number: %d\n", challenge_number);
          #endif

          size_t challenge_resp_size = 0;
          char challenge_response[A2S_MAX_SIZE] = {0};

          if (query_types[j].query_type == A2S_INFO)
          {
            memcpy(challenge_response, query_types[j].request_data, 25);
            memcpy(challenge_response + 25, &challenge_number, sizeof(challenge_number));
            challenge_resp_size = 29;
          }
          else
          {
            memcpy(challenge_response, "\xFF\xFF\xFF\xFF", 4);
            challenge_response[4] = query_types[j].query_type;
            memcpy(challenge_response + 5, &challenge_number, sizeof(challenge_number));
            challenge_resp_size = 9;
          }

          if (socket_client_send(&client, challenge_response, challenge_resp_size) != challenge_resp_size)
          {
            #ifdef A2S_DEBUG
            printf("Error sending challenge response\n");
            #endif
            continue;
          }

          n = socket_client_recv(&client, buffer, A2S_MAX_SIZE);
          if (n <= 0)
          {
            #ifdef A2S_DEBUG
            printf("Timeout or error occurred while receiving second response for challenge\n");
            #endif
            continue;
          }

          // Null-terminate the received data for safety
          buffer[n] = '\0';
        }

        // Fill the value structure
        val.size = n;
        memcpy(val.data, buffer, n);

        #ifdef A2S_DEBUG
        printf("Received valid data, filling map: IP = 0x%X, Port = %d, Value size = %llu\n", xdp_key.ip, ntohs(xdp_key.port), val.size);
        #endif

        int update_result = -1;
        switch (query_types[j].query_type)
        {
          case A2S_INFO:
          update_result = bpf_map_update_elem(xdp_maps->a2s_info, &xdp_key, &val, BPF_ANY);
          break;

          case A2S_PLAYERS:
          update_result = bpf_map_update_elem(xdp_maps->a2s_players, &xdp_key, &val, BPF_ANY);
          break;

          case A2S_RULES:
          update_result = bpf_map_update_elem(xdp_maps->a2s_rules, &xdp_key, &val, BPF_ANY);
          break;
        }

        if (update_result < 0)
        {
          perror("Failed to update XDP map");
        }
      }

      // Close the socket after processing all queries for the current server
      socket_client_close(&client);
    }

    // Sleep between query cycles to avoid overloading the servers
    sleep(A2S_QUERY_TIME_SEC);
  }

  return NULL;
}