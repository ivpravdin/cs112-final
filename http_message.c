#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "http_message.h"

#define INITIAL_SIZE 0xA00000

static int expand_data(struct HTTPMessage *message)
{
    int new_length = message->length * 2 + 2;
    char *new_data = realloc(message->data, new_length);
    assert(new_data != NULL);
    message->data = new_data;
    return new_length;
}

void clear_message(struct HTTPMessage *message)
{
    free(message->data);
    message->data = NULL;
    message->size = 0;
    message->length = 0;
}

// return -1 if connection is closed
// return 0 if message is incomplete
// return 1 if message is complete
// int read_message(struct HTTPMessage *message, char *overflow_buffer, int *overflow_length, int (*read_from_connection)(void *, char *, int), void *conn)
// {
//     int read_bytes;
//     char buffer[256];

//     if (message->data == NULL) {
//         message->size = INITIAL_SIZE;
//         message->data = calloc(message->size, 1);
//         assert(message->data != NULL);
//     }

//     if (*overflow_length > 0) {
//         if (message->length + *overflow_length > message->size) {
//             message->size = expand_data(message);
//         }
//         memcpy(&message->data[message->length], overflow_buffer, *overflow_length);
//         message->length += *overflow_length;
//         *overflow_length = 0;
//     }

//     read_bytes = read_from_connection(conn, &message->data[message->length], message->size - message->length);

//     printf("Read %d bytes\n", read_bytes); // Debugging

//     if (read_bytes <= 0) {
//         return -1;
//     }

//     message->length += read_bytes;

//     // if (strstr(message->data, "\r\n\r\n") != NULL) {
//     //     if (get_field(message, "Content-Length: ", buffer) > 0) {
//     //         int content_length = atoi(buffer);  
//     //         char *header_end = strstr(message->data, "\r\n\r\n");
//     //         int header_length = (header_end - message->data) + 4;
//     //         int total_length = header_length + content_length;

//     //         if (message->length > total_length) {
//     //             int extra_bytes = message->length - total_length;
//     //             memcpy(overflow_buffer, &message->data[total_length], extra_bytes);
//     //             *overflow_length = extra_bytes;
//     //             message->length = total_length;
//     //         }

//     //         if (message->length == total_length)
//     //             return 1;
//     //     } else {
//     //         char *header_end = strstr(message->data, "\r\n\r\n");
//     //         int header_length = header_end - message->data + 4;
//     //         if (message->length > header_length) {
//     //             int extra_bytes = message->length - header_length;
//     //             memcpy(overflow_buffer, message->data + header_length, extra_bytes);
//     //             *overflow_length = extra_bytes;
//     //             message->length = header_length;
//     //         }
//     //         return 1;
//     //     }
//     // }

//     // if (message->length == message->size) {
//     //     message->size = expand_data(message);
//     //     printf("Expanded data to %d\n", message->size); // Debugging
//     // }

//     return 1;
// }

// int get_method(struct HTTPMessage *message, char *method)
// {
//     char *end = strstr(message->data, " ");
//     if (end == NULL) {
//         return -1;
//     }

//     int length = end - message->data;
//     strncpy(method, message->data, length);
//     method[length] = '\0';
//     return length;
// }

// int get_field(struct HTTPMessage *message, const char *field_name, char *field_value)
// {
//     assert(message != NULL && message->data != NULL);
//     char *field = strcasestr(message->data, field_name);
//     if (field == NULL) {
//         return -1;
//     }

//     field += strlen(field_name);
//     char *end = strcasestr(field, "\r\n");
//     if (end == NULL) {
//         return -1;
//     }

//     int length = end - field;
//     strncpy(field_value, field, length);
//     field_value[length] = '\0';
//     return length;
// }