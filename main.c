#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "proxy.h"

Proxy global_proxy;

void handle_signal(int signal) {
    if (signal == SIGINT || signal == SIGTERM || signal == SIGQUIT || signal == SIGSEGV) {
        proxy_free(global_proxy);
        exit(0);
    }
}

void setup_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
}

int main(int argc, char *argv[])
{
    int errno;

    if (argc != 4) {
        printf("Usage: %s <port> <proxy X.509 certificate> <proxy private key>\n", argv[0]);
        exit(1);
    }

    setup_signal_handler();
    signal(SIGPIPE, SIG_IGN);

    global_proxy = proxy_init(atoi(argv[1]), argv[2], argv[3]);
    errno = proxy_run(global_proxy);
    proxy_free(global_proxy);
    return errno;
}