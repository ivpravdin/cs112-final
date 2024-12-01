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

#define MAX_HTTP_MESSAGE_SIZE 0xA00000

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
    c->flags = 0;
    init_message(&c->message, 0xA00000);

    return c;
}

void connection_free(connection c)
{
    if (c->using_ssl) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    close(c->fd);
    free_message(&c->message);
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


// 0 means 0 bytes, -1 means error or closed
int read_from_connection(connection c, char *buffer, int buffer_size)
{
    int bytes_read;
    int err;

    if (c->using_ssl) {
        while ((bytes_read = SSL_read(c->ssl, buffer, buffer_size)) <= 0) {
            err = SSL_get_error(c->ssl, bytes_read);
            if (err == SSL_ERROR_WANT_WRITE) {
                fd_set fd;
                FD_ZERO(&fd);
                FD_SET(c->fd, &fd);
                select(c->fd + 1, NULL, &fd, NULL, NULL);
            } else if (err == SSL_ERROR_WANT_READ) {
                return 0;
            } else {
                return -1;
            }
        }
    } else {
        bytes_read = read(c->fd, buffer, buffer_size);
        if (bytes_read <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            } else {
                return -1;
            }
        }
    }

    return bytes_read;
}

int write_to_connection(connection c, char *buffer, int length)
{
    int bytes_written;

    if (c->using_ssl) {
        while ((bytes_written = SSL_write(c->ssl, buffer, length)) <= 0) {
            int err = SSL_get_error(c->ssl, bytes_written);
            if (err == SSL_ERROR_WANT_WRITE) {
                fd_set fd;
                FD_ZERO(&fd);
                FD_SET(c->fd, &fd);
                select(c->fd + 1, NULL, &fd, NULL, NULL);
            } else if (err == SSL_ERROR_WANT_READ) {
                fd_set fd;
                FD_ZERO(&fd);
                FD_SET(c->fd, &fd);
                select(c->fd + 1, &fd, NULL, NULL, NULL);
            } else {
                return -1;
            }
        }
    } else {
        bytes_written = write(c->fd, buffer, length);
    }

    return bytes_written;
}

