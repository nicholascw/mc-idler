#include <limits.h>

typedef struct conn_info {
  int connfd;
  int filefd;
  unsigned short len;
  unsigned short offset;
  char buf[PIPE_BUF];
} conn_info_t;

int socket_epoll_listen(char *hostname, char *port);
void socket_epoll_loop(int listen_fd, void (*fsm)(conn_info_t *));
