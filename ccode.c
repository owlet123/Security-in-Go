// Openssl.cpp : Defines the entry point for the console application.

//#include "stdafx.h"

// OpenSSL headers 
#include <openssl/bio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

// Default PSK identity and key
static char *psk_identity = "Client_identity";
char *psk_key = "aaaa";

static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
		unsigned int max_identity_len,
		unsigned char *psk,
		unsigned int max_psk_len) {
	int ret;
	long key_len = 4L; // rewritten from unsigned int = 4;
	unsigned char *key;

	if (hint) printf("Received PSK identity hint '%s'\n", hint);
	
	// lookup PSK identity and PSK key based on the given identity hint here
	
	ret = BIO_snprintf(identity, max_identity_len, "%s", psk_identity);
	
	if (ret < 0 || (unsigned int)ret > max_identity_len) return 0;

	printf("created identity '%s' len=%d\n", identity, ret);
	
	key = (unsigned char*) psk_key;
	printf("psk_key = %s\n", key);
	if (key_len > max_psk_len) {
		printf("psk buffer of callback is too small (%ld) for key (%ld)\n", max_psk_len, key_len);
		return 0;
	}
	memcpy(psk, key, key_len);

	return key_len;
}

BIO * conn(char* add) {
	SSL_CTX *ctx;
	BIO *bio;
	SSL *ssl;

	ctx = SSL_CTX_new(TLSv1_client_method());

	bio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(bio, &ssl);
	if (!ssl) {
		printf("Can't locate SSL pointer\n");
		return NULL;
	}

	BIO_set_conn_hostname(bio, add);
	BIO_get_ssl(bio, ssl);

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	SSL_set_psk_client_callback(ssl, psk_client_cb);

	int e = BIO_do_connect(bio);
	printf("BIO_do_connect(bio): %d\n", e);

	if (e == -1) return NULL;

	return bio;
}

void init() {
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	SSL_library_init();
}

int C_bio_write(BIO *bio, const char * buff, int len) {
	len++;
	char * buf = (char*) malloc(len * sizeof(char));
	
	strcpy(buf, buff);
	strcat(buf, "\0");
	
	printf("writing... %s ", buf);

	if (BIO_write(bio, buf, len) <= 0) {
		if (!BIO_should_retry(bio)) {
			printf("Error while BIO_read - failed write.\n");
			return 0;
		}
		// Do something to handle the retry
	}
	printf("...OK\n");

	return 1;
}

char* C_bio_read(BIO * bio) {
	char* buf = (char*)malloc(sizeof(char));
	int len = 1;
	buf[0] = '\0';
	bool t = true;
	while(t) {
		char* buf_tmp = (char*)malloc(2*sizeof(char));
		buf_tmp[1] = '\0';

		int x = BIO_read(bio, buf_tmp, 1);
		if (x == 0) {
			printf("Error while BIO_read - connection closed.\n");
		} else if (x < 0) {
			if (!BIO_should_retry(bio)) {
				printf("Error while BIO_read - failed read.\n");
			}
			// Do something to handle the retry 
		}
		
		if (*buf_tmp == '\0') {
			t = false;
		} else {
			len++;
			buf = (char*) realloc(buf, len * (sizeof(char)));		
			strcat(buf, buf_tmp);
		}
		free(buf_tmp);
	}	
	printf("reading... %s ...OK\n", buf);

	return buf;
}

int main() {
	init();
	BIO* bio = conn("localhost:10443");
	
	return 0;
}