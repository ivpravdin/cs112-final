#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "http_message.h"

#define INITIAL_SIZE 0xA00000

void init_message(struct HTTPMessage *message, int size)
{
    message->data = calloc(size, 1);
    assert(message->data != NULL);
    message->size = size;
    message->length = 0;
}

void free_message(struct HTTPMessage *message)
{
    free(message->data);
    message->data = NULL;
}

bool is_complete(struct HTTPMessage *message)
{
    char *header_end, *content_length_str;
    int content_length, total_length;

    header_end = strstr(message->data, "\r\n\r\n");
    if (header_end == NULL)
        return false;

    content_length_str = strstr(message->data, "Content-Length: ");
    if (content_length_str != NULL && content_length_str < header_end) {
        content_length = atoi(content_length_str + strlen("Content-Length: "));
        total_length = (header_end - message->data) + 4 + content_length;
        return message->length >= total_length;
    }

    return true;
}

void clear_message(struct HTTPMessage *message)
{
    if (message != NULL) {
        message->length = 0;
    }
}

void expand_data(struct HTTPMessage *message)
{
    message->size = message->size * 2 + 1;
    message->data = realloc(message->data, message->size);
    assert(message->data != NULL);
}

int get_method(char *message, char *method, int max_length)
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
        return -1;
    }

    int field_name_len = strlen(field_name);
    int field_value_len = strlen(field_value);
    int total_field_len = field_name_len + field_value_len + 4;

    char *field_start = strcasestr(message->data, field_name);
    if (field_start && field_start < header_end) {
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
            if (message->length + shift >= message->size) {
                expand_data(message);
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
        if (message->length + total_field_len >= message->size) {
            expand_data(message);
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