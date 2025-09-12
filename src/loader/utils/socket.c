#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#include "socket.h"

#define SOCKET_TIMEOUT_SEC 1 // 1 second timeout

// Initialize and prepare UDP client socket
int socket_client_prepare(udp_client_t *client, const char *ip, int port)
{
  // Create UDP socket (SOCK_DGRAM is assumed, IPPROTO_UDP is default)
  client->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (client->sockfd < 0)
  {
    perror("Socket creation failed");
    return -1;
  }

  // Set socket receive timeout (1 second timeout)
  struct timeval timeout = {SOCKET_TIMEOUT_SEC, 0};

  if (setsockopt(client->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
  {
    perror("setsockopt SO_RCVTIMEO failed");
    close(client->sockfd);
    return -1;
  }

  // Set up sockaddr_in structure
  client->addr.sin_family = AF_INET;
  client->addr.sin_port = htons(port);

  if (inet_pton(AF_INET, ip, &client->addr.sin_addr) <= 0)
  {
    perror("Invalid IP address format");
    close(client->sockfd);
    return -1;
  }

  return 0;
}

// Send data to the server using the UDP socket
int socket_client_send(udp_client_t *client, const char *data, size_t len)
{
  int sent_bytes = sendto(client->sockfd, data, len, 0, (struct sockaddr *)&client->addr, sizeof(client->addr));

  if (sent_bytes < 0)
  {
    perror("sendto failed");
  }

  return sent_bytes;
}

// Receive data from the server
int socket_client_recv(udp_client_t *client, char *buffer, size_t bufsize)
{
  socklen_t len = sizeof(client->addr);

  // Perform the recvfrom operation
  int n = recvfrom(client->sockfd, buffer, bufsize - 1, 0, (struct sockaddr *)&client->addr, &len);

  if (n < 0)
  {
    // We don’t need to check EAGAIN/EWOULDBLOCK here since the socket is blocking
    // Return 0 for timeout when socket is blocking
    if (errno == EAGAIN || errno == EWOULDBLOCK)
    return 0;

    perror("recvfrom failed");
    return -1;
  }
  
  // Null-terminate the received data for safety
  buffer[n] = '\0';
  
  return n;
}

// Close the socket gracefully
void socket_client_close(udp_client_t *client)
{
  if (client->sockfd >= 0)
  {
    close(client->sockfd);

    // Mark the fd as invalid
    client->sockfd = -1;
  }
}