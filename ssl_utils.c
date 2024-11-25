#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ssl_utils.h"

void InitializeSSL()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

X509 *LoadCertificate(const char *filename)
{
    FILE *cert_file = fopen(filename, "r");
    if (cert_file == NULL) {
        perror("Failed to open certificate file");
        exit(1);
    }

    X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (cert == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    fclose(cert_file);
    return cert;
}

EVP_PKEY *LoadPrivateKey(const char *filename)
{
    FILE *key_file = fopen(filename, "r");
    if (key_file == NULL) {
        perror("Failed to open private key file");
        exit(1);
    }

    EVP_PKEY *key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    if (key == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    fclose(key_file);
    return key;
}

// Used when connecting to a client
SSL *CreateClientSSL(X509 *cert, EVP_PKEY *key, int sockfd)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);

    if (SSL_set_fd(ssl, sockfd) == 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_set_options(ssl, SSL_OP_IGNORE_UNEXPECTED_EOF) == 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_set_mode(ssl, SSL_MODE_ASYNC) == 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_free(ctx);

    return ssl;
}

SSL *CreateServerSSL(char *hostname, int sockfd)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_set_tlsext_host_name(ssl, hostname) == 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_set_fd(ssl, sockfd) == 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_set_options(ssl, SSL_OP_IGNORE_UNEXPECTED_EOF) == 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_set_mode(ssl, SSL_MODE_ASYNC) == 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_free(ctx);

    return ssl;
}

X509 *GenerateCertificate(char *hostname, X509 *issuer_cert, EVP_PKEY *issuer_key)
{
    X509 *cert = X509_new();
    if (cert == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Set the certificate version
    if (X509_set_version(cert, 3) != 1) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return NULL;
    }

    // Set the serial number
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    if (serial == NULL) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return NULL;
    }

    unsigned char serial_bytes[20];
    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) {
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        X509_free(cert);
        return NULL;
    }

    BIGNUM *bn = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
    if (bn == NULL) {
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        X509_free(cert);
        return NULL;
    }

    if (!BN_to_ASN1_INTEGER(bn, serial)) {
        ERR_print_errors_fp(stderr);
        BN_free(bn);
        ASN1_INTEGER_free(serial);
        X509_free(cert);
        return NULL;
    }

    BN_free(bn);
    
    if (!X509_set_serialNumber(cert, serial)) {
        ERR_print_errors_fp(stderr);
        ASN1_INTEGER_free(serial);
        X509_free(cert);
        return NULL;
    }

    ASN1_INTEGER_free(serial);

    // Set the issuer
    X509_NAME *issuer_name = X509_get_subject_name(issuer_cert);
    if (X509_set_issuer_name(cert, issuer_name) != 1) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return NULL;
    }

    // Set the subject
    X509_NAME *subject_name = X509_NAME_new();
    if (subject_name == NULL) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return NULL;
    }

    X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC, (unsigned char *)hostname, -1, -1, 0);
    if (X509_set_subject_name(cert, subject_name) != 1) {
        ERR_print_errors_fp(stderr);
        X509_NAME_free(subject_name);
        X509_free(cert);
        return NULL;
    }

    X509_NAME_free(subject_name);

    // Set the validity period
    X509_gmtime_adj(X509_get_notBefore(cert), -31536000L); // 1 year ago
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 year

    // Set the public key
    if (X509_set_pubkey(cert, issuer_key) != 1) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return NULL;
    }

    // Add SAN extension
    X509_EXTENSION *san_ext = NULL;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer_cert, cert, NULL, NULL, 0);

    // Example: Add SAN for the given hostname
    char san_value[256];
    snprintf(san_value, sizeof(san_value), "DNS:%s", hostname);

    san_ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san_value);
    if (san_ext == NULL) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return NULL;
    }

    // Add the SAN extension to the certificate
    if (X509_add_ext(cert, san_ext, -1) != 1) {
        ERR_print_errors_fp(stderr);
        X509_EXTENSION_free(san_ext);
        X509_free(cert);
        return NULL;
    }

    // Clean up
    X509_EXTENSION_free(san_ext);

    // Sign the certificate
    if (X509_sign(cert, issuer_key, EVP_sha256()) == 0) {
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        return NULL;
    }

    // Save the certificate to a file
    FILE *cert_file = fopen("certificate.pem", "w");
    if (cert_file == NULL) {
        perror("Failed to open file for writing");
        X509_free(cert);
        return NULL;
    }

    if (PEM_write_X509(cert_file, cert) != 1) {
        ERR_print_errors_fp(stderr);
        fclose(cert_file);
        X509_free(cert);
        return NULL;
    }

    fclose(cert_file);

    return cert;
}