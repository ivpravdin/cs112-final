#ifndef __HTTP_MESSAGE_H__
#define __HTTP_MESSAGE_H__

struct HTTPMessage {
    char *data;
    int size;   // Size of the data buffer
    int length; // Length of the data in the buffer
};

void clear_message(struct HTTPMessage *message);
//int read_message(struct HTTPMessage *message, char *overflow_buffer, int *overflow_length, int (*read_from_connection)(void *, char *, int), void *conn);
//int get_method(struct HTTPMessage *message, char *method);
//int get_field(struct HTTPMessage *message, const char *field_name, char *field_value);

#endif // __HTTP_MESSAGE_H__