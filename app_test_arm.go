package main

/*
//#cgo CFLAGS: -IC:/OpenSSL-Win64/include/include
#cgo LDFLAGS: -lcrypto -lssl
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
char *psk_key;
static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
		unsigned int max_identity_len,
		unsigned char *psk,
		unsigned int max_psk_len) {
	int ret;
	long key_len = 4L; // rewritten from unsigned int = 4;
	unsigned char *key;
	//if (hint) printf("Received PSK identity hint '%s'\n", hint);
	
	// lookup PSK identity and PSK key based on the given identity hint here
	
	ret = BIO_snprintf(identity, max_identity_len, "%s", psk_identity);
	
	if (ret < 0 || (unsigned int)ret > max_identity_len) return 0;
	//printf("created identity '%s' len=%d\n", identity, ret);
	
	key = (unsigned char*) psk_key;
	//printf("psk_key = %s\n", key);
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
	//printf("BIO_do_connect(bio): %d\n", e);
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
	
	//printf("writing... %s ", buf);
	if (BIO_write(bio, buf, len) <= 0) {
		if (!BIO_should_retry(bio)) {
			printf("Error while BIO_read - failed write.\n");
			return 0;
		}
		// Do something to handle the retry
	}
	//printf("...OK\n");
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
	//printf("reading... %s ...OK\n", buf);
	return buf;
}
*/
import "C"
import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rsa"
	"crypto/rand"
	"encoding/pem"
	"net"
	"log"
	"os"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
)

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			//fmt.Println(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func checkErr(err error) {
    if err != nil {
        log.Fatal("ERROR:", err)
    }
}

func check_arrguments(server, port, key, keystore, ip, dn, cert_type string) {
	if _, err := strconv.Atoi(port); err != nil {
		log.Fatalf("Error: not correct port")
	}
	if _, err := os.Stat(keystore); os.IsNotExist(err) {
		log.Fatalf("Error: not correct path to keystore")
	}
	if net_ip := net.ParseIP(ip); net_ip == nil {
		log.Fatalf("Error: not correct format IP")
	}
	if cert_type != "CA" && cert_type != "END" {
		log.Fatalf("error: not correct certificate type (CA/END)")
	} 
	//fmt.Println("Correct arguments")
}

func create_connection(server, port, private_key string) *C.BIO {
	C.psk_key = C.CString(private_key)

	C.init()
	return C.conn(C.CString(server + ":" + port))
}

func protocol_version_exchange(bio *C.BIO) int {
	if bio == nil {
		return -2
	}

	protocol_version := C.CString("1")
	err_write := C.C_bio_write(bio, protocol_version, 1)
	if err_write != 1 {
		log.Fatalf("error while writting protocol version")
	}

	server_protocol_version := C.C_bio_read(bio)
	//fmt.Printf("Server protocol version: %s", C.GoString(server_protocol_version))
	if *server_protocol_version != *protocol_version {
		return -1
	} 
	return 0
}

func generate_key(bio *C.BIO, cert_type string) (interface{}, string) {
	if bio == nil {
		return nil, "Error while connection"
	}
	
	sub_id := C.CString("SPOC") //ZMENIT NA UA
	err_write := C.C_bio_write(bio, sub_id, 4) //ZMENIT NA 2
	if err_write != 1 {
		return nil, "error while writting component id"
	}

	if cert_type == "CA" || cert_type == "END" {
		//correct
	} else {
		return nil, "Error: not correct certificate type"
	} 
	
	ca_info := C.CString(cert_type)
	err_write = C.C_bio_write(bio, ca_info, C.int(len(cert_type)))
	if err_write != 1 {
		return nil, "error while writting ca info"
	}

	key_length := C.C_bio_read(bio)
	//fmt.Println("server key length: ", C.GoString(key_length))
	key_len, err := strconv.Atoi(C.GoString(key_length))	
	checkErr(err)
		
	if key_len <= 0 {
		return nil, "Error: size of key must be at least 2-bit"
	}
	
	var key interface{}
	key, err = rsa.GenerateKey(rand.Reader, key_len)
	checkErr(err)
	
	return key, ""
}

func create_csr(bio *C.BIO, ip, dn string, key interface{}) string {
	if bio == nil {
		return ""
	}	
	template := &x509.CertificateRequest {
		Subject : pkix.Name{CommonName: ip},
		DNSNames : []string{dn},
		IPAddresses : []net.IP{net.ParseIP(ip)},
	}

	cert_req, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	checkErr(err)
	csr_out, err := os.Create("csr.pem")
	checkErr(err)
	pem.Encode(csr_out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: cert_req})
	csr_out.Close()
	//log.Printf("written csr.pem\n")
	
	return "csr.pem"
}

func sending_csr(bio *C.BIO, ip, file string) (int, string, string) {
	b, err := ioutil.ReadFile(file)
	checkErr(err)
	csr := C.CString(string(b))
	err_write := C.C_bio_write(bio, csr, C.int(len(string(b))))
	if err_write != 1 {
		return -1, "error while writting CSR", ""
	}

	err_write = C.C_bio_write(bio, C.CString(ip), C.int(len(ip)))
	if err_write != 1 {
		return -1, "error while writting ip", ""
	}
	
	cert_read := C.C_bio_read(bio)
	str := C.GoString(cert_read)
	
	if !(strings.HasPrefix(str, "-----BEGIN")) {
		return -1, "error: not correct certificate", ""
	} 
	
	return 0, "", str
}

func save_cert(cert, path string) int {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return -1
	}
	
	if !(strings.HasPrefix(cert, "-----BEGIN")) {
		log.Fatalf("error: not correct certificate")
	} 
	
	cert_out, err := os.Create(path + "cert.pem")
	checkErr(err)
	_, err = cert_out.Write([]byte(cert))
	checkErr(err)
	
	cert_out.Close()
	
	if _, err := os.Stat(path + "cert.pem"); os.IsNotExist(err) {
		return -1
	}
	return 0
}

func save_key(key interface{}, path string) int {
	if key == nil {
		return -1
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return -1
	}
	key_out, err := os.OpenFile(path + "key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // [tmp, tmp/]
	checkErr(err)
	err = pem.Encode(key_out, pemBlockForKey(key))
	checkErr(err)
	
	key_out.Close()	
	
	if _, err := os.Stat(path + "key.pem"); os.IsNotExist(err) {
		return -1
	}
	
	return 0
}

func main() {
	t0 := time.Now()

	arg := os.Args 
	if len(arg) < 8 {
		log.Fatalf("Too few arguments. [server, port, key, path, subjectIp, subjectDN, certificate_type]")
	} else if len(arg) > 8 {
		log.Fatalf("Too many arguments.[server, port, key, path, subjectIp, subjectDN, certificate_type]")
	}
	
	server      := arg[1]
	port        := arg[2] 
	private_key := arg[3]
	path	    := arg[4]
	ip 	    	:= arg[5]
	dn          := arg[6]
	cert_type   := arg[7]	
		
	check_arrguments(server, port, private_key, path, ip, dn, cert_type)

	//1. connection
	bio := create_connection(server, port, private_key)
	if bio == nil {
		log.Fatalf("error while connecting to server, wrong server or key")
	}

	//2. protocol version exchange
	if ret := protocol_version_exchange(bio); ret == -1 {
		log.Fatalf("error: different version")
	} else {
		//fmt.Println(" ...OK")
	}
	
	//3. key length
	key, e := generate_key(bio, cert_type)
	if key == nil {
		log.Fatalf(e)
	} else {
		//fmt.Println("correct key")
	}
	
	//4. certificate signing
	file := create_csr(bio, ip, dn, key)

	ret, e, cert := sending_csr(bio, ip, file)
	if ret == -1 {
		log.Fatalf(e)
	} else {
		//fmt.Println("server sends correct certificate")
	}

	os.Remove("csr.pem")
	
	//saving certificate
	if ret := save_cert(cert, path); ret == 0 {
		//log.Printf("written %s/cert.pem\n", path)
	} else if ret == -1 {
		log.Fatalf("Error while saving certificate")
	}
	
	//saving key
	if ret := save_key(key, path); ret == 0 {
		//log.Printf("written %s/key.pem\n", path)
	} else if ret == -1 {
		log.Fatalf("Error while saving key")
	}
	
	//5. achieving trust
	at := C.C_bio_read(bio)
	str := C.GoString(at)
	
	if !(strings.HasPrefix(str, "-----BEGIN")) {
		log.Fatalf("error: not correct trust anchor")
	} else {
		//fmt.Println("correct trust anchor")
	}
	//server terminates the connection
	fmt.Printf("Correct.\n")
	C.free(unsafe.Pointer(bio))
	C.free(unsafe.Pointer(C.psk_key))
	t1 := time.Now()
	fmt.Printf("The call took %v to run.\n", t1.Sub(t0))

}