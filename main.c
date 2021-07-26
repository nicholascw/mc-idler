/* https://wiki.vg/Protocol */

#include "fsm.h"
#include "socket.h"

int main() {
  int fd = socket_epoll_listen("localhost", "25565");
  if (fd)
    socket_epoll_loop(fd, &fsm);
  else
    return 1;
  return 0;
}
