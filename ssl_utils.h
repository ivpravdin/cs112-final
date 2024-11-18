#ifndef __SSL_UTILS_H__
#define __SSL_UTILS_H__

#include <openssl/ssl.h>

void InitializeSSL();
X509 *LoadCertificate(const char *filename);
EVP_PKEY *LoadPrivateKey(const char *filename);
SSL_CTX *CreateSSLContext(X509 *cert, EVP_PKEY *key);
X509 *GenerateCertificate(char *hostname, X509 *issuer_cert, EVP_PKEY *issuer_key);

#endif // __SSL_UTILS_H__