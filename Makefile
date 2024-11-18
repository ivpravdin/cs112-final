src = $(wildcard *.c)
obj = $(src:.c=.o)
CC = gcc
LDFLAGS = -lnsl -lssl -lcrypto

a.out: $(obj)
	$(CC) -g -Wall -Wextra -Werror -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) a.out
