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
#include <fcntl.h>
#include <ctype.h>

#include "proxy.h"
#include "connection_list.h"
#include "ssl_utils.h"

#define DEBUG printf

#define DEFAULT_PORT "80"
#define DEFAULT_SSL_PORT "443"
#define BUFFER_SIZE 0xA00000

typedef int (*generic_read)(void *, char *, int);

typedef struct Proxy {
    SOCKET sockfd;
    connection_list cl;
    X509 *ca;
    EVP_PKEY *key;
} *Proxy;

Proxy proxy_init(int port, const char *ca_filename, const char *key_filename)
{
    int optval;
         
    Proxy p = malloc(sizeof(struct Proxy));
    p->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    p->cl = connection_list_init();

    optval = 1;
    setsockopt(p->sockfd, SOL_SOCKET, SO_REUSEADDR, 
	     (const void *)&optval , sizeof(int));

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

inline static void make_socket_non_blocking(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

static void accept_new_client(Proxy p)
{
    connection c = init_connection();

    c->fd = accept(p->sockfd, NULL, NULL);
    make_socket_non_blocking(c->fd);
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

    make_socket_non_blocking(serverfd);

    DEBUG("Connected to server: %s:%s\n", server, port);

    freeaddrinfo(servaddr);
    
    return serverfd;
}

static void ssl_error(Proxy p, connection c)
{
    disconnect_connection(p, c);
}

static void init_SSL_connection(Proxy p, connection c, char *hostname)
{
    if (c->using_ssl)
        return;

    if (c->role == 0) {
        SSL_CTX *server_ctx = SSL_CTX_new(TLS_client_method());
        SSL *server_ssl = SSL_new(server_ctx);
        SSL_set_tlsext_host_name(server_ssl, hostname);
        SSL_set_fd(server_ssl, c->peer->fd);
        SSL_set_options(server_ssl, SSL_OP_IGNORE_UNEXPECTED_EOF);
        SSL_set_mode(server_ssl, SSL_MODE_ASYNC | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

        while (-1 == SSL_connect(server_ssl))
        {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(c->peer->fd, &fds);

            switch (SSL_get_error(server_ssl, -1))
            {
                case SSL_ERROR_WANT_READ:
                    select(c->peer->fd + 1, &fds, NULL, NULL, NULL);
                    break;
                case SSL_ERROR_WANT_WRITE:
                    select(c->peer->fd + 1, NULL, &fds, NULL, NULL);
                    break;
                default:
                    SSL_CTX_free(server_ctx);
                    ssl_error(p, c);
                    return;
            }
        }

        c->peer->ssl = server_ssl;
        c->peer->using_ssl = 1;

        SSL_CTX_free(server_ctx);

        DEBUG("SSL connection initialized for server\n");

        // Client-side (client to proxy)
        X509 *cert = GenerateCertificate(hostname, p->ca, p->key);
        SSL_CTX *client_ctx = SSL_CTX_new(TLS_server_method());
        SSL_CTX_use_certificate(client_ctx, cert);
        SSL_CTX_use_PrivateKey(client_ctx, p->key);
        SSL *client_ssl = SSL_new(client_ctx);
        SSL_set_fd(client_ssl, c->fd);
        SSL_set_options(client_ssl, SSL_OP_IGNORE_UNEXPECTED_EOF);
        SSL_set_mode(client_ssl, SSL_MODE_ASYNC | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

        while (-1 == SSL_accept(client_ssl))
        {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(c->fd, &fds);
            ERR_print_errors_fp(stdout);

            switch (SSL_get_error(client_ssl, -1))
            {
                case SSL_ERROR_WANT_READ:
                    select(c->fd + 1, &fds, NULL, NULL, NULL);
                    break;
                case SSL_ERROR_WANT_WRITE:
                    select(c->fd + 1, NULL, &fds, NULL, NULL);
                    break;
                default:
                    SSL_free(client_ssl);
                    SSL_CTX_free(client_ctx);
                    X509_free(cert);
                    ssl_error(p, c);
                    return;
            }
        }

        c->ssl = client_ssl;
        c->using_ssl = 1;

        DEBUG("SSL connection initialized for client\n");

        SSL_CTX_free(client_ctx);
        X509_free(cert);
    }
}

static int get_method(char *message, char *method, int max_length)
{
    char *end = strstr(message, " ");
    if (end == NULL) {
        return -1;
    }

    int length = end - message > max_length - 1 ? max_length - 1 : end - message;
    strncpy(method, message, length);
    method[length] = '\0';
    return length;
}

int get_field(char *message, const char *field_name, char *field_value, int max_length)
{
    char *field = strcasestr(message, field_name);
    if (field == NULL) {
        return -1;
    }

    field += strlen(field_name);
    char *end = strcasestr(field, "\r\n");
    if (end == NULL) {
        return -1;
    }

    int length = end - field > max_length - 1 ? max_length - 1 : end - field;
    strncpy(field_value, field, length);
    field_value[length] = '\0';
    return length;
}

static int process_message(Proxy p, connection c, char *buffer, int buffer_length)
{
    char method[16];
    char hostname_and_port[262];
    char hostname[256];
    char port[16] = {0};
    char CONNECT_response[] = "HTTP/1.1 200 OK\r\n\r\n";
    get_method(buffer, method, 16);

    char *accept_encoding = strcasestr(buffer, "Accept-Encoding:");
    if (c->role == 0 && accept_encoding != NULL) {
        char *end = strstr(accept_encoding, "\r\n");
        if (end != NULL) {
            memmove(accept_encoding, end + 2, buffer_length - (end + 2 - buffer));
            buffer_length -= (end + 2 - accept_encoding);
        }
    }

// for (int i = 0; i <= buffer_length - 3; i++) {
//     if (strncmp(&buffer[i], "the", 3) == 0) {
//         buffer[i] = 'l';
//         buffer[i + 1] = 'o';
//         buffer[i + 2] = 'l';
//     }
// }

    if (c->peer == NULL) {
        get_field(buffer, "Host: ", hostname_and_port, 256);
        sscanf(hostname_and_port, "%255[^:]:%15s", hostname, port);

        if (port[0] == '\0') {
            if (strcmp(method, "CONNECT") == 0)
                strcpy(port, DEFAULT_SSL_PORT);
            else
                strcpy(port, DEFAULT_PORT);
        }

        int serverfd = connect_to_server(hostname, port);
        if (serverfd < 0) {
            disconnect_connection(p, c);
            return -1;
        }
        connection server = init_connection();
        server->fd = serverfd;
        c->peer = server;
        server->peer = c;
        server->role = 1;
        add_connection(p->cl, server);

        if (strcmp(method, "CONNECT") == 0){
            write_to_connection(c, CONNECT_response, strlen(CONNECT_response));
            init_SSL_connection(p, c, hostname);
        } else {
            write_to_connection(server, buffer, buffer_length);
        }
    } else {
        write_to_connection(c->peer, buffer, buffer_length);
    }
}

static int read_message(connection c, char *buffer, int buffer_size)
{
    int bytes_read = 0;

    if (c->using_ssl) {
        bytes_read = SSL_read(c->ssl, buffer, buffer_size);
        if (bytes_read <= 0) {
            int ssl_err = SSL_get_error(c->ssl, bytes_read);
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                return 0;
            } else {
                printf("Error reading from SSL connection\n");
                return -1;
            }
        }
        return bytes_read;
    } else {
        printf("c->fd: %d, c->using_ssl: %d\n", c->fd, c->using_ssl);
        bytes_read = read(c->fd, buffer, buffer_size);
        if (bytes_read <= 0) {
            return -1;
        }
    }
}

int proxy_run(Proxy p) 
{
    fd_set fds;
    int max_fd;
    struct timeval timeout = {0, 0};

    char *buffer = malloc(BUFFER_SIZE);
    int buffer_length;

    while(1) {
        max_fd = get_max_fd(p->cl);
        max_fd = max_fd > p->sockfd ? max_fd : p->sockfd;
        fds = get_fd_set(p->cl);
        FD_SET(p->sockfd, &fds);

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

                while(0 == (buffer_length = read_message(c, buffer, BUFFER_SIZE)))
                    ;

                if (buffer_length < 0) {
                    DEBUG("Connection closed %d\n", sock);
                    disconnect_connection(p, c);
                } else {
                    process_message(p, c, buffer, buffer_length);
                }
            }
        }
    }
}