/* https://wiki.vg/Protocol */

#include "fsm.h"
#include "socket.h"
int main(int argc, char **argv) {
  int fd;
  if (argc == 3)
    fd = socket_epoll_listen(argv[1], argv[2]);
  else
    fd = socket_epoll_listen("::", "25565");
  if (fd)
    socket_epoll_loop(fd, &fsm);
  else
    return 1;
  return 0;
}
