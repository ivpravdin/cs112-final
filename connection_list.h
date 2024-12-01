/* 10/21/2024
 * Ivan Pravdin
 * CS112: 2
 * 
 * clieent_list.h: Connection list header
 */
#ifndef __CONNECTION_LIST_H__
#define __CONNECTION_LIST_H__

#include <stdbool.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <stdbool.h>

#include "http_message.h"

#define SOCKET unsigned int

typedef struct connection_list *connection_list;
typedef struct connection *connection;

struct connection {
    int role;                                        // 0 for client, 1 for server
    SOCKET fd;                                       // File descriptor for the connection socket
    connection peer;                                 // The peer connection
    bool using_ssl;                                  // Whether the connection is using SSL
    SSL *ssl;                                        // SSL context for the connection
    unsigned int flags;
    struct HTTPMessage message;                      // The HTTP message from the connection
};

/**
 * @brief Initializes a new connection list.
 * @return A pointer to the initialized connection list.
 */
connection_list connection_list_init();

connection init_connection();

void connection_free(connection c);

/**
 * @brief Frees the memory allocated for the connection list.
 * @param cl The connection list to free.
 */
void connection_list_free(connection_list cl);

/**
 * @brief Adds a new connection to the connection list.
 * @param cl The connection list.
 * @param c The connection to add.
 */
void add_connection(connection_list cl, connection c);

/**
 * @brief Removes a connection from the connection list.
 * @param cl The connection list.
 * @param c The connection to remove.
 */
void remove_connection(connection_list cl, connection c);

/**
 * @brief Gets a connection by its file descriptor.
 * @param cl The connection list.
 * @param fd The file descriptor of the connection.
 * @return The connection associated with the given file descriptor.
 */
connection get_connection(connection_list cl, unsigned int fd);

/**
 * @brief Gets the file descriptor set for select.
 * @param cl The connection list.
 * @return The file descriptor set.
 */
fd_set get_fd_set(connection_list cl);

/**
 * @brief Gets the maximum file descriptor from the connection list.
 * @param cl The connection list.
 * @return The maximum file descriptor.
 */
int get_max_fd(connection_list cl);

int read_from_connection(connection c, char *buffer, int length);
int write_to_connection(connection c, char *buffer, int length);

#endif // __CONNECTION_LIST_H__