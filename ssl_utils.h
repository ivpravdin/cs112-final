#ifndef __SSL_UTILS_H__
#define __SSL_UTILS_H__

#include <openssl/ssl.h>

void InitializeSSL();
X509 *LoadCertificate(const char *filename);
EVP_PKEY *LoadPrivateKey(const char *filename);
SSL *CreateClientSSL(X509 *cert, EVP_PKEY *key, int sockfd);
SSL *CreateServerSSL(char *hostname, int sockfd);
X509 *GenerateCertificate(char *hostname, X509 *issuer_cert, EVP_PKEY *issuer_key);

#endif // __SSL_UTILS_H__