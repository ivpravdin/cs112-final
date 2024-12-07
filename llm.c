#include "llm.h"
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LLM_URL "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev"
#define LLM_API_KEY "x-api-key: "

static size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    size_t total_size = size * nmemb;
    strncpy(data, ptr, total_size);
    data[total_size] = '\0';
    return total_size;
}

int get_OPTIONS_response(char* response)
{
    char OPTIONS_response[] = "HTTP/1.1 204 No Content\r\n"
                              "Access-Control-Allow-Origin: *\r\n"
                              "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                              "Access-Control-Allow-Headers: x-api-key, Content-Type\r\n"
                              "Access-Control-Max-Age: 86400\r\n"
                              "Vary: Origin\r\n"
                              "\r\n";

    strncpy(response, OPTIONS_response, strlen(OPTIONS_response));
    response[strlen(OPTIONS_response)] = '\0';
    return strlen(OPTIONS_response);
}

void process_POST_request(char *request, char* response)
{
    CURL* curl;
    CURLcode res;
    struct curl_slist* headers = NULL;

    curl = curl_easy_init();

    curl_easy_setopt(curl, CURLOPT_URL, LLM_URL);
    headers = curl_slist_append(headers, LLM_API_KEY);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    FILE *debug_file = fopen("request_debug.log", "w");
    if (debug_file) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_STDERR, debug_file);
    }

    curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl); 

    fclose(debug_file);
}