#ifndef __PROXY_H__
#define __PROXY_H__

typedef struct Proxy *Proxy;

Proxy proxy_init(int port, const char *ca_filename, const char *key_filename);
void proxy_free(Proxy p);
int proxy_run(Proxy p);

#endif // __PROXY_H__