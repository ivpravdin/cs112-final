src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
CFLAGS = -g
LDFLAGS = -lnsl -lssl -lcrypto -lcurl

a.out: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(obj) a.out
