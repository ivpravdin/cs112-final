#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

#include "proxy.h"
#include "connection_list.h"
#include "ssl_utils.h"

#define DEBUG printf

#define DEFAULT_PORT "80"
#define DEFAULT_SSL_PORT "443"

typedef int (*generic_read)(void *, char *, int);

typedef struct Proxy {
    SOCKET sockfd;
    connection_list cl;
    X509 *ca;
    EVP_PKEY *key;
} *Proxy;

Proxy proxy_init(int port, const char *ca_filename, const char *key_filename)
{
    Proxy p = malloc(sizeof(struct Proxy));
    p->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    p->cl = connection_list_init();

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(p->sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind");
        exit(1);
    }
    listen(p->sockfd, 5);

    InitializeSSL();

    p->ca = LoadCertificate(ca_filename);
    p->key = LoadPrivateKey(key_filename);

    DEBUG("Proxy initialized\n");

    return p;
}

void proxy_free(Proxy p)
{
    close(p->sockfd);
    connection_list_free(p->cl);
    X509_free(p->ca);
    EVP_PKEY_free(p->key);
    free(p);
    DEBUG("Proxy freed\n");
}

static void accept_new_client(Proxy p)
{
    connection c = init_connection();

    c->fd = accept(p->sockfd, NULL, NULL);
    add_connection(p->cl, c);

    DEBUG("New client connected\n");
}

static void disconnect_connection(Proxy p, connection c)
{
    if (c->peer != NULL) {
        DEBUG("Connection closed %d\n", c->peer->fd);
        remove_connection(p->cl, c->peer);
        connection_free(c->peer);
    } 

    if (c != NULL) {
        DEBUG("Connection closed %d\n", c->fd);
        remove_connection(p->cl, c);
        connection_free(c);
    }
}

static int connect_to_server(const char* server, char *port)
{
    int err;
    int serverfd;
    struct addrinfo *servaddr;
    struct addrinfo hints = {
        .ai_family = AF_INET
    };
    
    getaddrinfo(server, port, &hints, &servaddr);

    serverfd = socket(servaddr->ai_family, 
                      servaddr->ai_socktype, 
                      servaddr->ai_protocol);

    err = connect(serverfd, servaddr->ai_addr, servaddr->ai_addrlen);
    if (err != 0) {
        perror("Server connect");
        return err;
    }

    DEBUG("Connected to server: %s:%s\n", server, port);

    freeaddrinfo(servaddr);
    
    return serverfd;
}

static void init_SSL_connection(Proxy p, connection c, char *hostname)
{
    if (c->using_ssl)
        return;

    if (c->role == 0) {
        // Server-side (proxy to server)
        SSL_CTX *server_ctx = SSL_CTX_new(TLS_client_method()); // Use client method here
        SSL *server_ssl = SSL_new(server_ctx);
        SSL_set_fd(server_ssl, c->peer->fd);
        if (SSL_connect(server_ssl) != 1) {
            ERR_print_errors_fp(stderr);
            DEBUG("SSL connection failed for server\n");
            SSL_CTX_free(server_ctx);
            return;
        }
        c->peer->ssl = server_ssl;
        c->peer->using_ssl = 1;

        SSL_CTX_free(server_ctx);

        DEBUG("SSL connection initialized for server\n");

        // Client-side (client to proxy)
        X509 *cert = GenerateCertificate(hostname, p->ca, p->key);
        SSL_CTX *client_ctx = CreateSSLContext(cert, p->key);
        SSL *client_ssl = SSL_new(client_ctx);
        SSL_set_fd(client_ssl, c->fd);
        if (SSL_accept(client_ssl) != 1) {
            ERR_print_errors_fp(stderr);
            DEBUG("SSL connection failed for client\n");
            SSL_CTX_free(client_ctx);
            return;
        }
        c->ssl = client_ssl;
        c->using_ssl = 1;

        DEBUG("SSL connection initialized for client\n");

        SSL_CTX_free(client_ctx);
        X509_free(cert);
    }
}

static int process_message(Proxy p, connection c)
{
    char method[16];
    char hostname_and_port[256];
    char hostname[256];
    char port[6] = {0};
    char CONNECT_response[] = "HTTP/1.1 200 OK\r\n\r\n";
    get_method(&c->message, method);

    DEBUG("Processing message with method: %s\n", method);

    if (c->peer == NULL) {
        get_field(&c->message, "Host: ", hostname_and_port);
        sscanf(hostname_and_port, "%[^:]:%s", hostname, port);

        if (port[0] == '\0') {
            if (strcmp(method, "CONNECT") == 0)
                strcpy(port, DEFAULT_SSL_PORT);
            else
                strcpy(port, DEFAULT_PORT);
        }

        int serverfd = connect_to_server(hostname, port);
        connection server = init_connection();
        server->fd = serverfd;
        c->peer = server;
        server->peer = c;
        add_connection(p->cl, server);
    }

    if (strcmp(method, "CONNECT") == 0) {
        write_to_connection(c, CONNECT_response, strlen(CONNECT_response));
        DEBUG("CONNECT response sent to client\n");
        init_SSL_connection(p, c, hostname);
    } else {
        write_to_connection(c->peer, c->message.data, c->message.length);
        DEBUG("Message sent to server %s\n", c->message.data);
    }
}



int proxy_run(Proxy p) 
{
    fd_set fds;
    int max_fd;
    while(1) {
        fds = get_fd_set(p->cl);
        FD_SET(p->sockfd, &fds);
        max_fd = get_max_fd(p->cl);
        max_fd = (max_fd > p->sockfd) ? max_fd : p->sockfd;
        select(max_fd + 1, &fds, NULL, NULL, NULL);

        DEBUG("Select returned\n");

        if (FD_ISSET(p->sockfd, &fds))
            accept_new_client(p);

        for (int sock = 0; sock <= max_fd; sock++) {
            if (sock == p->sockfd)
                continue;
            
            if (FD_ISSET(sock, &fds)) {
                DEBUG("Data available on socket %d\n", sock);
                connection c = get_connection(p->cl, sock);
                if (c == NULL) {
                    close(sock);
                    continue;
                }

                int status = read_message(&c->message, c->overflow_buffer, &c->overflow_length, (generic_read) read_from_connection, c);

                DEBUG("Read message status: %d\n", status);

                if (status == -1)
                    disconnect_connection(p, c);

                if (status == 1) {
                    process_message(p, c);
                    clear_message(&c->message);
                }
            }
        }
    }
}