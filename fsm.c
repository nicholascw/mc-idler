#include "fsm.h"

#include <arpa/inet.h>
#include <limits.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "log.h"
#include "varint.h"

static void _fsm_epoll_remove(conn_info_t *conn, int epollfd) {
  epoll_ctl(epollfd, EPOLL_CTL_DEL, conn->connfd, NULL);
  close(conn->connfd);
  if (conn->buf) free(conn->buf);
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

static _fsm_buf_ret_t _fsm_recv(conn_info_t *conn, int len, int epollfd,
                                char *buf) {
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

static uint64_t _fsm_parse_handshake(char *buf, ssize_t buflen) {
  if (buf[0] != 0) {
    // packet_id is not handshake
    return -1;
  }
  char *ptr = buf + 1;
  varint_t *vproto_ver = varint_from_buf(ptr, buflen - 1);
  int64_t proto_ver = varint_to_int64(vproto_ver);
  L_DEBUGF("Protocol Version Number: %ld", proto_ver);
  ptr += vproto_ver->len;
  if (vproto_ver) free(vproto_ver);
  if (proto_ver == -1) return -1;
  varint_t *vhost_len = varint_from_buf(ptr, buflen - (ptr - buf));
  int64_t host_len = varint_to_int64(vhost_len);
  ptr += vhost_len->len;
  if (vhost_len) free(vhost_len);
  if (host_len == -1) return -1;
  if (ptr + host_len >= buf + buflen) {
    // claimed hostname longer than packet
    return -1;
  }
  char *str_hostname = strndup(ptr, host_len);
  if (!str_hostname) {
    L_PERROR();
    L_ERR("Read hostname failed.");
  }
  ptr += host_len;
  uint16_t port;
  memcpy(&port, ptr, 2);
  port = ntohs(port);
  L_DEBUGF("client thinks it's connecting to: %s:%d", str_hostname, port);
  free(str_hostname);
  ptr += 2;
  varint_t *vnext_state = varint_from_buf(ptr, buflen - (ptr - buf));
  uint64_t next_state = varint_to_int64(vnext_state);
  L_DEBUGF(
      "Next State: %s",
      (next_state == 1 ? "Status" : (next_state == 2 ? "Login" : "WTF?!")));
  if (vnext_state) free(vnext_state);
  return next_state;
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
        // check nextstate here
        varint_t *v_pktid = varint_from_buf(conn->buf, conn->current_buf_len);
        int64_t pktid = varint_to_int64(v_pktid);
        if (v_pktid) free(v_pktid);
        switch (pktid) {
          case 0: {
            L_DEBUGF("Received handshake from fd=%d", conn->connfd);
            int64_t next_state =
                _fsm_parse_handshake(conn->buf, conn->current_buf_len);
            if (next_state != 1 && next_state != 2)
              _fsm_epoll_remove(conn, epollfd);
            else {
              conn->state = next_state;
              _fsm_epollout_enable(conn, epollfd);
            }
          } break;
          case 1: {
          } break;
          default: {
            L_ERRF("Unknown Packet ID received: 0x%02lx", pktid);
            _fsm_epoll_remove(conn, epollfd);
          } break;
        }
      }
    } break;
    case 1: {
      // respond server list ping here
      _fsm_epoll_remove(conn, epollfd);
    } break;
    case 2: {
      // handle login request here
      _fsm_epoll_remove(conn, epollfd);
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
