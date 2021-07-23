CFLAGS= -I. -g3 -O3 -Wall -Wextra -Wunused-variable -Wmissing-prototypes -D _GNU_SOURCE
LIBS=
SRC=$(wildcard *.c)
HDR=$(wildcard *.h)
OBJS=$(patsubst %.c, obj/%.o, $(SRC))

.PHONY: all clean

all: clean obj mc_idler format

format:
	$(foreach n, $(SRC), clang-format -style=google -i $(n); )
	$(foreach n, $(HDR), clang-format -style=google -i $(n); )

mc_idler: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	$(RM) -r obj mc_idler

obj/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

obj:
	mkdir -p obj

