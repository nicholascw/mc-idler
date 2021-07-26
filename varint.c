#include "varint.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"

int64_t varint_to_int64(const varint_t *in) {
  if (!in) return -1;
  int64_t out = 0;
  for (int i = 0; i < in->len; i++)
    out = out | ((0x7f & in->data[i]) << (i * 7));
  return out;
}

varint_t *int64_to_varint(const int64_t in) {
  uint8_t buf[10];
  uint8_t i;
  for (i = 0; i < 10; i++) {
    buf[i] = 0x7f & (in >> (7 * i));
    if (!(in >> (7 * i)))
      break;
    else
      buf[i] = 0x80 | buf[i];
  }
  varint_t *out = malloc(2 + i);
  if (!out) {
    L_PERROR();
    return NULL;
  }
  out->len = i + 1;
  memcpy(out->data, buf, i + 1);
  return out;
}

varint_t *varint_from_buf(const char *buf, const ssize_t len) {
  if (len <= 0) return NULL;
  uint8_t counter = 0;
  while (((*(buf + counter)) & 0x80) &&
         (counter < (len - 1 < 10 ? len - 1 : 10)))
    counter++;
  varint_t *out = calloc(2 + counter, sizeof(uint8_t));
  if (!out) {
    L_PERROR();
    return NULL;
  }
  out->len = counter + 1;
  memcpy(out->data, buf, counter + 1);
  return out;
}
