/* 10/21/2024
 * Ivan Pravdin
 * CS112: 2
 * 
 * connection_list.c: Connection list implementation
 */
#include <stdlib.h> 
#include <string.h>
#include <time.h>
#include <stdio.h> // remove later
#include <unistd.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "connection_list.h"

#define SSL_FRAME_SIZE 16384
#define OVERFLOW_BUFFER_SIZE 0xFFFF

struct connection_list {
    struct connection *connection;          // Head always NULL for connection
    struct connection_list *next;
};

connection_list connection_list_init()
{
    connection_list cl = malloc(sizeof(struct connection_list));
    assert(cl != NULL);

    cl->connection = NULL;
    cl->next = NULL;

    return cl;
}

connection init_connection()
{
    connection c = malloc(sizeof(struct connection));
    assert(c != NULL);

    c->role = 0;
    c->fd = 0;
    c->peer = NULL;
    c->using_ssl = false;
    c->ssl = NULL;
    c->overflow_buffer = malloc(OVERFLOW_BUFFER_SIZE);
    c->overflow_length = 0;
    c->message.data = NULL;
    c->message.size = 0;
    c->message.length = 0;

    return c;
}

void connection_free(connection c)
{
    close(c->fd);
    if (c->using_ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    free(c->overflow_buffer);
    clear_message(&c->message);
    free(c);
}

void connection_list_free(connection_list cl)
{
    connection_list next;
    while (cl != NULL) {
        next = cl->next;
        if (cl->connection != NULL)
            connection_free(cl->connection);
        free(cl);
        cl = next;
    }
}

void add_connection(connection_list cl, connection c)
{
    connection_list new = malloc(sizeof(struct connection_list));
    assert(new != NULL);

    new->connection = c;
    new->next = NULL;
    
    while (cl->next != NULL) {
        cl = cl->next;
    }
    cl->next = new;
}

void remove_connection(connection_list cl, connection c)
{
    connection_list prev = cl;
    cl = cl->next;
    while (cl != NULL) {
        if (cl->connection == c) {
            prev->next = cl->next;
            free(cl);
            return;
        }
        prev = cl;
        cl = cl->next;
    }
}

connection get_connection(connection_list cl, unsigned int fd)
{
    cl = cl->next;
    while (cl != NULL) {
        if (cl->connection->fd == fd) {
            return cl->connection;
        }
        cl = cl->next;
    }
    return NULL;
}

fd_set get_fd_set(connection_list cl)
{
    fd_set fds;
    FD_ZERO(&fds);

    cl = cl->next;
    while (cl != NULL) {
        FD_SET(cl->connection->fd, &fds);
        cl = cl->next;
    }
    
    return fds;
}

int get_max_fd(connection_list cl)
{
    int max = 0;

    cl = cl->next;
    while (cl != NULL) {
        if (cl->connection->fd > max) {
            max = cl->connection->fd;
        }
        cl = cl->next;
    }

    return max;
}

int read_from_connection(connection c, char *buffer, int length)
{
    if (c->using_ssl) {
        int bytes_read = 0;
        bytes_read = SSL_read(c->ssl, buffer, length);
        if (bytes_read <= 0) {
            printf("Error reading from SSL connection\n");
            ERR_print_errors_fp(stdout);
        }
        return bytes_read;
    } else {
        return read(c->fd, buffer, length);
    }
}

int write_to_connection(connection c, char *buffer, int length)
{
    if (c->using_ssl) {
        int bytes_written = 0;
        for (int i = 0; i < length; i += SSL_FRAME_SIZE)
            bytes_written += SSL_write(c->ssl, buffer + i, length - i > SSL_FRAME_SIZE ? SSL_FRAME_SIZE : length - i);
        return bytes_written;
    } else {
        return write(c->fd, buffer, length);
    }
}

