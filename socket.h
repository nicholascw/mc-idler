#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#ifndef EPOLL_ERRS
#define EPOLL_ERRS (EPOLLRDHUP | EPOLLERR | EPOLLHUP)
#endif

#ifndef conn_info__
#define conn_info__
typedef struct conn_info {
  int connfd;
  uint32_t state;
  ssize_t target_packet_len;
  ssize_t current_buf_len;
  char *buf;
} conn_info_t;
#endif

int socket_epoll_listen(char *hostname, char *port);
void socket_epoll_loop(int listen_fd, void (*fsm)(conn_info_t *, int));
