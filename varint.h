#include <stdint.h>

typedef struct {
  uint8_t len;
  uint8_t data[];
} varint_t;

int64_t varint_to_int64(const varint_t *in);
varint_t *int64_to_varint(const int64_t in);
varint_t *varint_from_buf(const char *buf);
