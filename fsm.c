#include "fsm.h"

#include <arpa/inet.h>
#include <limits.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "dummy_response.h"
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

static void _fsm_epollin_enable(conn_info_t *conn, int epollfd) {
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLL_ERRS;
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

static uint8_t _fsm_send(conn_info_t *conn) {
  char *ptr = conn->buf + conn->current_buf_len;
  int send_ret =
      send(conn->connfd, ptr, conn->target_packet_len - conn->current_buf_len,
           MSG_DONTWAIT);
  if (send_ret <= 0) {
    if (!(errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK))
      L_PERROR();
    return 0;
  }

  L_DEBUGF("sent fd=%d %d byte(s)", conn->connfd, send_ret);
  conn->current_buf_len += send_ret;
  if (conn->current_buf_len >= conn->target_packet_len)
    return 1;
  else
    return 0;
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

static void _fsm_state_waitall(conn_info_t *conn, int epollfd) {
  L_DEBUG("State -1 entered.");
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
  free(packet_len);
  conn->state = 0;
  L_DEBUGF("State -1 => State 0 with target_packet_len=%ld",
           conn->target_packet_len);
}

static void _fsm_state_parse_inbound(conn_info_t *conn, int epollfd) {
  L_DEBUG("State 0 entered.");
  // receive remaining packet with length specified by packet length parsed
  _fsm_buf_ret_t rbuf =
      _fsm_recv(conn, conn->target_packet_len - conn->current_buf_len, epollfd,
                conn->buf + conn->current_buf_len);
  if (rbuf.ret < 0) return;
  conn->current_buf_len += rbuf.ret;
  if (conn->current_buf_len >= conn->target_packet_len) {
    // packet id check
    varint_t *v_pktid = varint_from_buf(conn->buf, conn->current_buf_len);
    int64_t pktid = varint_to_int64(v_pktid);
    if (v_pktid) free(v_pktid);
    switch (pktid) {
      case 0: {
        if (conn->target_packet_len == 1) {
          // empty request, drop directly
          if (conn->buf) free(conn->buf);
          conn->state = -1;
          conn->buf = NULL;
          conn->target_packet_len = -1;
          conn->current_buf_len = 0;
        } else {
          // check nextstate here
          L_DEBUGF("Received handshake from fd=%d", conn->connfd);
          int64_t next_state =
              _fsm_parse_handshake(conn->buf, conn->current_buf_len);
          if (next_state != 1 && next_state != 2)
            _fsm_epoll_remove(conn, epollfd);
          else {
            if (conn->buf) free(conn->buf);
            conn->state = next_state;
            conn->buf = NULL;
            conn->target_packet_len = -1;
            conn->current_buf_len = 0;
            _fsm_epollout_enable(conn, epollfd);
          }
        }
      } break;
      case 1: {
        // respond ping-pong
        memmove(conn->buf + 1, conn->buf, conn->target_packet_len);
        conn->buf[0] = conn->target_packet_len;
        conn->current_buf_len = 0;
        conn->state = 1;
        conn->target_packet_len++;
        _fsm_epollout_enable(conn, epollfd);
      } break;
      default: {
        L_ERRF("Unknown Packet ID received: 0x%02lx", pktid);
        _fsm_epoll_remove(conn, epollfd);
      } break;
    }
  }
}

static void _fsm_state_send_status(conn_info_t *conn, int epollfd) {
  L_DEBUG("State 1 entered.");
  if (conn->buf == NULL) {
    // construct send buffer with dummy json response
    int64_t total_packet_len = strlen(str_dummy_json_response);
    varint_t *v_str_len = int64_to_varint(total_packet_len);
    total_packet_len += v_str_len->len + 1;  // 1 is packet id 0x00
    varint_t *v_packet_len = int64_to_varint(total_packet_len);
    total_packet_len += v_packet_len->len;
    conn->buf = malloc(total_packet_len);
    if (!conn->buf) {
      L_PERROR();
      _fsm_epoll_remove(conn, epollfd);
    }
    char *ptr = conn->buf;
    memcpy(ptr, v_packet_len->data, v_packet_len->len);
    ptr += v_packet_len->len;
    ptr[0] = 0;
    ptr++;
    memcpy(ptr, v_str_len->data, v_str_len->len);
    ptr += v_str_len->len;
    memcpy(ptr, str_dummy_json_response, strlen(str_dummy_json_response));
    conn->target_packet_len = total_packet_len;
    conn->current_buf_len = 0;
    free(v_str_len);
    free(v_packet_len);
  }
  if (_fsm_send(conn)) {
    free(conn->buf);
    conn->buf = NULL;
    conn->state = -1;
    conn->target_packet_len = -1;
    conn->current_buf_len = 0;
    _fsm_epollin_enable(conn, epollfd);
  }
}

void fsm(conn_info_t *conn, int epollfd) {
  if (!conn) return;
  switch (conn->state) {
    case -1: {
      _fsm_state_waitall(conn, epollfd);
    } break;
    case 0: {
      _fsm_state_parse_inbound(conn, epollfd);
    } break;
    case 1: {
      _fsm_state_send_status(conn, epollfd);
    } break;
    case 2: {
      L_DEBUG("State 2 entered.");
      // handle login request here
      _fsm_epoll_remove(conn, epollfd);
    } break;
  }
}
