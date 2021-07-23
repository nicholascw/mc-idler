#include "socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"

#define EPOLL_ERRS (EPOLLRDHUP | EPOLLERR | EPOLLHUP)

static void *_socket_get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

static int _socket_set_nonblk(int fd) {
  return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

int socket_epoll_listen(char *hostname, char *port) {
  int listen_fd;
  struct addrinfo hints, *servinfo, *p;
  int rv;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;  // use my IP
  if ((rv = getaddrinfo(hostname, port, &hints, &servinfo)) != 0) {
    L_ERRF("getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }
  // loop through all the results and bind to the first we can
  int yes = 1;
  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) ==
        -1) {
      L_PERROR();
      continue;
    }
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) ==
        -1) {
      L_PERROR();
      exit(1);
    }
    if (bind(listen_fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(listen_fd);
      L_PERROR();
      continue;
    }
    break;
  }
  if (!p) {
    L_ERR("failed to bind.");
    exit(1);
  }
  freeaddrinfo(servinfo);
  if (listen(listen_fd, SOMAXCONN) == -1) {
    L_PERROR();
    exit(1);
  }
  if (_socket_set_nonblk(listen_fd) == -1) {
    L_PERROR();
  }
  return listen_fd;
}

void socket_epoll_loop(int listen_fd, void (*fsm)(conn_info_t *)) {
  socklen_t sin_size;
  char s[INET6_ADDRSTRLEN];
  int new_fd;
  struct sockaddr_storage their_addr;  // connector's address information
  int epollfd = epoll_create1(0);
  if (epollfd == -1) {
    L_PERROR();
    exit(1);
  }
  struct epoll_event ev;
  ev.data.fd = listen_fd;
  ev.events = EPOLLIN;
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_fd, &ev) == -1) {
    L_PERROR();
    exit(1);
  }

  struct epoll_event events[128];
  memset(events, 0, sizeof(events));

  L_INFO("Entering epoll loop...");
  while (1) {
    int cnt_fd = epoll_wait(epollfd, events, 128, -1);
    if (cnt_fd > 0) {
      for (int i = 0; i < cnt_fd; i++) {
        int this_evfd = events[i].data.fd == listen_fd
                            ? listen_fd
                            : ((conn_info_t *)events[i].data.ptr)->connfd;
        if (events[i].events & EPOLL_ERRS) {
          L_ERRF("Error occured on fd=%d, closing...", this_evfd);
          free(events[i].data.ptr);
          close(this_evfd);
          epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
          continue;
        }
        if (this_evfd == listen_fd) {
          // new connection
          sin_size = sizeof their_addr;
          new_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &sin_size);
          if (new_fd == -1) {
            L_PERROR();
          } else {
            inet_ntop(their_addr.ss_family,
                      _socket_get_in_addr((struct sockaddr *)&their_addr), s,
                      sizeof s);
            L_INFOF("fd=%d got connection from %s", new_fd, s);
          }
          if (_socket_set_nonblk(listen_fd) == -1) {
            L_PERROR();
          }
          conn_info_t *new_conn = calloc(1, sizeof(conn_info_t));
          if (!new_conn) {
            L_PERROR();
            L_ERRF("failed to allocate space for fd=%d, closing socket...",
                   new_fd);
            close(new_fd);
          } else {
            ev.data.ptr = new_conn;
            new_conn->connfd = new_fd;
            ev.events = EPOLLIN | EPOLL_ERRS;
            if (epoll_ctl(epollfd, EPOLL_CTL_ADD, new_fd, &ev) == -1) {
              L_PERROR();
              L_ERRF("failed to add fd=%d into epoll, closing socket...",
                     new_fd);
              free(new_conn);
              close(new_fd);
            } else {
              L_INFOF("fd=%d added %s to epoll succesfully.", new_fd, s);
            }
          }
        } else {
          // existing connection
          conn_info_t *this_conn = events[i].data.ptr;
          if (events[i].events & EPOLLIN) {
            if (this_conn->filefd == -1) continue;
            // read in header
            int ret = recv(this_evfd, this_conn->buf + this_conn->len,
                           PIPE_BUF - this_conn->len - 1, 0);
            if (ret < 0) {
              if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
                continue;
              else {
                L_PERROR();
                L_ERRF(
                    "Error when receiving HTTP header from fd=%d, closing...",
                    this_evfd);
                free(this_conn);
                epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
                close(this_evfd);
                continue;
              }
            }
            this_conn->buf[this_conn->len + ret] = '\0';

            // handle buffer here

            // enable listening for EPOLLOUT event
            ev.data.ptr = events[i].data.ptr;
            ev.events = EPOLLOUT | EPOLL_ERRS;
            if (epoll_ctl(epollfd, EPOLL_CTL_MOD, this_evfd, &ev) == -1) {
              L_PERROR();
            }
          } else if (events[i].events & EPOLLOUT) {
            // write out file
            if (this_conn->len > 0) {
              int send_ret =
                  send(this_evfd, this_conn->buf,
                       this_conn->len + this_conn->offset, MSG_DONTWAIT);
              if (send_ret > 0) {
                L_DEBUGF("sent fd=%d %d byte(s)", this_evfd, send_ret);
                if (send_ret < this_conn->len - this_conn->offset) {
                  this_conn->offset += send_ret;
                } else {
                  if (this_conn->filefd > 0) {
                    // read more file in
                    int read_ret =
                        read(this_conn->filefd, this_conn->buf, PIPE_BUF);
                    if (read_ret > 0) {
                      L_DEBUGF("read in %d bytes to fd=%d buffer from fd=%d",
                               read_ret, this_evfd, this_conn->filefd);
                      this_conn->len = read_ret;
                      this_conn->offset = 0;
                    } else if (read_ret == 0) {
                      // close connection
                      epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
                      close(this_evfd);
                      close(this_conn->filefd);
                      free(this_conn);
                    } else {
                      if (errno == EAGAIN || errno == EINTR ||
                          errno == EWOULDBLOCK)
                        continue;
                      else
                        L_PERROR();
                    }
                  } else {
                    // close connection
                    L_INFOF("close fd=%d due to eof@fd=%d.", this_evfd,
                            this_conn->filefd);
                    epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
                    close(this_evfd);
                    close(this_conn->filefd);
                    free(this_conn);
                  }
                }
              } else {
                if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
                  continue;
                else
                  L_PERROR();
              }
            } else {
              // close connection
              L_INFOF("close fd=%d due to buffer len=0.", this_evfd);
              epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
              close(this_evfd);
              close(this_conn->filefd);
              free(this_conn);
            }
          } else {
            L_DEBUG("Unknown epoll events returned.");
          }
        }
      }
    } else if (cnt_fd < 0) {
      L_PERROR();
    }
  }
}