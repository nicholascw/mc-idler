#include <limits.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "log.h"
#include "socket.h"
#include "varint.h"

static void _fsm_epoll_remove(conn_info_t *conn, int epollfd) {
  epoll_ctl(epollfd, EPOLL_CTL_DEL, conn->connfd, NULL);
  close(conn->connfd);
  free(conn);
}

static void _fsm_epollout_enable(conn_info_t *conn, int epollfd) {
  struct epoll_event ev;
  ev.events = EPOLLOUT | EPOLL_ERRS;
  ev.data.ptr = conn;
  if (epoll_ctl(epollfd, EPOLL_CTL_MOD, conn->connfd, &ev) == -1) {
    L_PERROR();
    _fsm_epoll_remove(conn, epollfd);
  }
}
typedef struct {
  char *buf;
  ssize_t ret;
} _fsm_buf_ret_t;

static _fsm_buf_ret_t _fsm_recv(conn_info_t *conn, int len, int epollfd, char *buf) {
  _fsm_buf_ret_t r = {.buf = NULL, .ret = -1};
  r.buf = buf ? buf : malloc(len);
  if (!r.buf) {
    L_PERROR();
    return r;
  }
  r.ret = recv(conn->connfd, r.buf, len, 0);
  if (r.ret <= 0) {
    if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK || r.ret == 0)
      return r;
    L_PERROR();
    L_ERRF("Error when receiving client packet from fd=%d, closing...",
           conn->connfd);
    _fsm_epoll_remove(conn, epollfd);
  }
  return r;
}

void fsm(conn_info_t *conn, int epollfd) {
  if (!conn) return;
  switch (conn->state) {
    case -1: {
      _fsm_buf_ret_t rbuf = _fsm_recv(conn, 5, epollfd, NULL);
      varint_t *packet_len = varint_from_buf(rbuf.buf, rbuf.ret);
      if (!packet_len) {
        L_ERRF("Failed to parse packet length, closing fd=%d", conn->connfd);
        _fsm_epoll_remove(conn, epollfd);
      }
      conn->target_packet_len = varint_to_int64(packet_len);
      conn->current_buf_len = rbuf.ret - packet_len->len;
      conn->buf = malloc(conn->target_packet_len + 1);
      if (!conn->buf) {
        L_PERROR();
        L_ERRF("Failed to allocate buffer for incoming packet from fd=%d",
               conn->connfd);
        _fsm_epoll_remove(conn, epollfd);
        free(rbuf.buf);
        return;
      }
      conn->buf[conn->target_packet_len] = '\0';
      if (rbuf.ret - packet_len->len > 0) {
        memcpy(conn->buf, rbuf.buf + (packet_len->len), conn->current_buf_len);
      }
      free(rbuf.buf);
      conn->state = 0;
    } break;
    case 0: {
      _fsm_buf_ret_t rbuf =
          _fsm_recv(conn, conn->target_packet_len - conn->current_buf_len,
                    epollfd, conn->buf + conn->current_buf_len);
      if (rbuf.ret < 1) return;
      conn->current_buf_len += rbuf.ret;
      if (conn->current_buf_len >= conn->target_packet_len) {
        _fsm_epollout_enable(conn, epollfd);
        conn->state = 1;
        // check nextstate here
      }
    } break;
    case 1: {
      // response server list ping here

    } break;
    case 2: {
      // handle login request here
    } break;
  }
}

/*
  // read in header

  int ret = recv(this_conn->connfd, this_conn->buf + this_conn->len,
                 PIPE_BUF - this_conn->len - 1, 0);
  if (ret < 0) {
    if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
      continue;
    else {
      L_PERROR();
      L_ERRF(
          "Error when receiving client handshake packet from fd=%d, "
          "closing...",
          this_evfd);
      free(this_conn);
      epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
      close(this_evfd);
      continue;
    }
  } else if (!ret)
    break;

  this_conn->buf[this_conn->len + ret] = '\0';

  // enable listening for EPOLLOUT event

  ev.data.ptr = events[i].data.ptr;
  ev.events = EPOLLOUT | EPOLL_ERRS;
  if (epoll_ctl(epollfd, EPOLL_CTL_MOD, this_evfd, &ev) == -1) {
    L_PERROR();
  }

  // close connection
  L_INFOF("close fd=%d due to eof@fd=%d.", this_evfd, this_conn->filefd);
  epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
  close(this_evfd);
  free(this_conn);

  // write out file
  if (this_conn->len > 0) {
    int send_ret = send(this_evfd, this_conn->buf,
                        this_conn->len + this_conn->offset, MSG_DONTWAIT);
    if (send_ret > 0) {
      L_DEBUGF("sent fd=%d %d byte(s)", this_evfd, send_ret);
      if (send_ret < this_conn->len - this_conn->offset) {
        this_conn->offset += send_ret;
      } else {
        if (this_conn->filefd > 0) {
          // read more file in
          int read_ret = read(this_conn->filefd, this_conn->buf, PIPE_BUF);
          if (read_ret > 0) {
            L_DEBUGF("read in %d bytes to fd=%d buffer from fd=%d", read_ret,
                     this_evfd, this_conn->filefd);
            this_conn->len = read_ret;
            this_conn->offset = 0;
          } else if (read_ret == 0) {
            // close connection
            epoll_ctl(epollfd, EPOLL_CTL_DEL, this_evfd, NULL);
            close(this_evfd);
            close(this_conn->filefd);
            free(this_conn);
          } else {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
              continue;
            else
              L_PERROR();
          }
        } else {
        }
      }
    } else {
      if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK)
        continue;
      else
        L_PERROR();
    }
  } else {
  }
}

*/
