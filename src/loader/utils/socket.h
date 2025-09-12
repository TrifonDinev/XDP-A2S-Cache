#pragma once

#include <netinet/in.h>
#include <stdint.h>

typedef struct
{
  int sockfd;
  struct sockaddr_in addr;
} udp_client_t;

int socket_client_prepare(udp_client_t *client, const char *ip, int port);
int socket_client_send(udp_client_t *client, const char *data, size_t len);
int socket_client_recv(udp_client_t *client, char *buffer, size_t bufsize);
void socket_client_close(udp_client_t *client);