//10.0.5.228

package main


import (
	"testing"
	"crypto/rand"
	"crypto/rsa"
	"os"
)

//TEST WRONG ARGUMENTS

func Test_connection_OK(t *testing.T) {
	t.Log("Testing connection... ")
	
	psk_key := "aaaa"
	server := "localhost"
	port := "10443"
	
	bio := create_connection(server, port, psk_key)
	if bio == nil {
		t.Errorf("Error while connecting to server")
	}
	t.Log("Test OK")
}

func Test_connection_NOK_server(t *testing.T) {
	t.Log("Testing connection with wrong server... ")
	
	psk_key := "aaaa"
	server := "10.10.10.10"
	port := "10443"
	
	bio := create_connection(server, port, psk_key)
	if bio != nil {
		t.Errorf("Error: connection was correct despite wrong server")
	}
	t.Log("Test OK")
}

func Test_connection_NOK_port(t *testing.T) {
	t.Log("Testing connection with wrong port... ")
	
	psk_key := "aaaa"
	server := "localhost"
	port := "10"
	
	bio := create_connection(server, port, psk_key)
	if bio != nil {
		t.Errorf("Error: connection was correct despite wrong port")
	}
	t.Log("Test OK")
}

func Test_connection_NOK_key(t *testing.T) {
	t.Log("Testing connection with wrong key... ")
	
	psk_key := "aaa"
	server := "localhost"
	port := "10443"
	
	bio := create_connection(server, port, psk_key)
	if bio != nil {
		t.Errorf("Error: connection was correct despite wrong key")
	}
	t.Log("Test OK")
}

func Test_version_exchange_OK(t *testing.T) {
	t.Log("Testing protocol version exchange... ")
		
	bio := create_connection("localhost", "10443", "aaaa")
	if bio == nil {
		t.Errorf("Error while connecting to server")
	}
	
	if ret := protocol_version_exchange(bio); ret == -1 {
		t.Errorf("Error: different version")
	} else if ret == -2 {
		t.Errorf("Error: problem with connection")
	} 
	t.Log("Test OK")
}

func Test_version_exchange_NOK_server(t *testing.T) {
	t.Log("Testing protocol version exchange... ")
			
	if ret := protocol_version_exchange(nil); ret == -1 {
		t.Errorf("Error: different version")
	} else if ret == -2 {
		t.Log("Test OK")
	} else {
		t.Errorf("Error: problem with connection")
	}
}

func Test_generate_key_OK_CA(t *testing.T) {
	t.Log("Testing of generation key... ")
		
	bio := create_connection("localhost", "10443", "aaaa")
	if bio == nil {
		t.Errorf("Error while connecting to server")
	}
	
	if ret := protocol_version_exchange(bio); ret == -1 {
		t.Errorf("error: different version")
	} 
	
	key, e := generate_key(bio, "CA")
	
	if key == nil {
		t.Errorf(e)
	}
	t.Log("Test OK")
}

func Test_generate_key_OK_END(t *testing.T) {
	t.Log("Testing of generation key... ")
		
	bio := create_connection("localhost", "10443", "aaaa")
	if bio == nil {
		t.Errorf("Error while connecting to server")
	}
	
	if ret := protocol_version_exchange(bio); ret == -1 {
		t.Errorf("error: different version")
	} 
	
	key, e := generate_key(bio, "END")
	
	if key == nil {
		t.Errorf(e)
	}
	t.Log("Test OK")
}

func Test_generate_key_NOK_server(t *testing.T) {
	t.Log("Testing of generation key... ")
		
	key, e := generate_key(nil, "CA")
	
	if key != nil {
		t.Errorf(e)
	}
	t.Log("Test OK")
}

func Test_generate_key_NOK_type(t *testing.T) {
	t.Log("Testing of generation key... ")
		
	bio := create_connection("localhost", "10443", "aaaa")
	if bio == nil {
		t.Errorf("Error while connecting to server")
	}
	
	if ret := protocol_version_exchange(bio); ret == -1 {
		t.Errorf("error: different version")
	} 
	
	key, e := generate_key(bio, "ASDW")
	
	if key != nil {
		t.Errorf(e)
	}
	t.Log("Test OK")
}

func Test_create_csr_OK(t *testing.T) {
	t.Log("Testing creating certificate signing request... ")
	
	bio := create_connection("localhost", "10443", "aaaa")
	if bio == nil {
		t.Errorf("Error while connecting to server")
	}
	if ret := protocol_version_exchange(bio); ret == -1 {
		t.Errorf("Error: different version")
	} else if ret == -2 {
		t.Errorf("Error: problem with connection")
	} 
	key, e := generate_key(bio, "END")
	if key == nil {
		t.Errorf(e)
	}
	
	file := create_csr(bio, "10.0.0.0", "example.com", key)
	if file == "" {
		t.Errorf("Error while creating CSR")
	}
	if _, err := os.Stat(file); os.IsNotExist(err) {
		t.Errorf("Error while creating CSR")
	}
	t.Log("Test OK")
}

func Test_create_csr_NOK(t *testing.T) {
	t.Log("Testing creating certificate signing request... ")
	
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Error while generate key for test")
	}
	
	file := create_csr(nil, "10.0.0.0", "example.com", key)
	if file != "" {
		t.Errorf("Error: creating CSR was correct despite wrong connection")
	}
	t.Log("Test OK")
}

//AKO SA MA SERVER spravat ked mu poslem CSR so zlou dlzkou kluca?

func Test_send_csr_OK(t *testing.T) {
	t.Log("Testing sending certificate signing request... ")
	
	bio := create_connection("localhost", "10443", "aaaa")
	if bio == nil {
		t.Errorf("Error while connecting to server")
	}
	if ret := protocol_version_exchange(bio); ret == -1 {
		t.Errorf("Error: different version")
	} else if ret == -2 {
		t.Errorf("Error: problem with connection")
	} 
	key, e := generate_key(bio, "END")
	if key == nil {
		t.Errorf(e)
	}
	
	file := create_csr(bio, "10.0.0.0", "example.com", key)
	if file == "" {
		t.Errorf("Error while creating CSR")
	}
	
	ret, e, cert := sending_csr(bio, "10.0.0.0", file)
	if ret == -1 && cert != "" {
		t.Errorf(e)
	}
	t.Log("Test OK")
}

func Test_save_cert_OK(t *testing.T) {
	t.Log("Testing saving cerficate... ")
	
	const cert = `
-----BEGIN CERTIFICATE-----
MIIDIDCCAomgAwIBAgIENd70zzANBgkqhkiG9w0BAQUFADBOMQswCQYDVQQGEwJV
UzEQMA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2Vy
dGlmaWNhdGUgQXV0aG9yaXR5MB4XDTk4MDgyMjE2NDE1MVoXDTE4MDgyMjE2NDE1
MVowTjELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0VxdWlmYXgxLTArBgNVBAsTJEVx
dWlmYXggU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eTCBnzANBgkqhkiG9w0B
AQEFAAOBjQAwgYkCgYEAwV2xWGcIYu6gmi0fCG2RFGiYCh7+2gRvE4RiIcPRfM6f
BeC4AfBONOziipUEZKzxa1NfBbPLZ4C/QgKO/t0BCezhABRP/PvwDN1Dulsr4R+A
cJkVV5MW8Q+XarfCaCMczE1ZMKxRHjuvK9buY0V7xdlfUNLjUA86iOe/FP3gx7kC
AwEAAaOCAQkwggEFMHAGA1UdHwRpMGcwZaBjoGGkXzBdMQswCQYDVQQGEwJVUzEQ
MA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2VydGlm
aWNhdGUgQXV0aG9yaXR5MQ0wCwYDVQQDEwRDUkwxMBoGA1UdEAQTMBGBDzIwMTgw
ODIyMTY0MTUxWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUSOZo+SvSspXXR9gj
IBBPM5iQn9QwHQYDVR0OBBYEFEjmaPkr0rKV10fYIyAQTzOYkJ/UMAwGA1UdEwQF
MAMBAf8wGgYJKoZIhvZ9B0EABA0wCxsFVjMuMGMDAgbAMA0GCSqGSIb3DQEBBQUA
A4GBAFjOKer89961zgK5F7WF0bnj4JXMJTENAKaSbn+2kmOeUJXRmm/kEd5jhW6Y
7qj/WsjTVbJmcVfewCHrPSqnI0kBBIZCe/zuf6IWUrVnZ9NA2zsmWLIodz2uFHdh
1voqZiegDfqnc1zqcPGUIWVEX/r87yloqaKHee9570+sB3c4
-----END CERTIFICATE-----`

	ret := save_cert(cert, ".")
	if ret != 0 {
		t.Errorf("Error while saving certificate")
	}
	if _, err := os.Stat("cert.pem"); os.IsNotExist(err) {
		t.Errorf("Error: certificate does not exist")
	}
	t.Log("Test OK")
	os.Remove("cert.pem")
}

func Test_save_cert_NOK_path(t *testing.T) {
	t.Log("Testing saving cerficate... ")
	
	const cert = `
-----BEGIN CERTIFICATE-----
MIIDIDCCAomgAwIBAgIENd70zzANBgkqhkiG9w0BAQUFADBOMQswCQYDVQQGEwJV
UzEQMA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2Vy
dGlmaWNhdGUgQXV0aG9yaXR5MB4XDTk4MDgyMjE2NDE1MVoXDTE4MDgyMjE2NDE1
MVowTjELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0VxdWlmYXgxLTArBgNVBAsTJEVx
dWlmYXggU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eTCBnzANBgkqhkiG9w0B
AQEFAAOBjQAwgYkCgYEAwV2xWGcIYu6gmi0fCG2RFGiYCh7+2gRvE4RiIcPRfM6f
BeC4AfBONOziipUEZKzxa1NfBbPLZ4C/QgKO/t0BCezhABRP/PvwDN1Dulsr4R+A
cJkVV5MW8Q+XarfCaCMczE1ZMKxRHjuvK9buY0V7xdlfUNLjUA86iOe/FP3gx7kC
AwEAAaOCAQkwggEFMHAGA1UdHwRpMGcwZaBjoGGkXzBdMQswCQYDVQQGEwJVUzEQ
MA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2VydGlm
aWNhdGUgQXV0aG9yaXR5MQ0wCwYDVQQDEwRDUkwxMBoGA1UdEAQTMBGBDzIwMTgw
ODIyMTY0MTUxWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUSOZo+SvSspXXR9gj
IBBPM5iQn9QwHQYDVR0OBBYEFEjmaPkr0rKV10fYIyAQTzOYkJ/UMAwGA1UdEwQF
MAMBAf8wGgYJKoZIhvZ9B0EABA0wCxsFVjMuMGMDAgbAMA0GCSqGSIb3DQEBBQUA
A4GBAFjOKer89961zgK5F7WF0bnj4JXMJTENAKaSbn+2kmOeUJXRmm/kEd5jhW6Y
7qj/WsjTVbJmcVfewCHrPSqnI0kBBIZCe/zuf6IWUrVnZ9NA2zsmWLIodz2uFHdh
1voqZiegDfqnc1zqcPGUIWVEX/r87yloqaKHee9570+sB3c4
-----END CERTIFICATE-----`

	ret := save_cert(cert, "/tmppp") //directory does not exist
	if ret == 0 {
		t.Errorf("Error: cerficate was create despite non-exist path")
	}
	if _, err := os.Stat("cert.pem"); os.IsExist(err) {
		t.Errorf("Error: cerficate was create despite non-exist path")
	}
	t.Log("Test OK")
}

func Test_save_key_OK(t *testing.T) {
	t.Log("Testing saving key... ")

	var key interface{}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	checkErr(err)
	
	if ret := save_key(key, "."); ret == -1 {
		t.Errorf("Error while saving key")
	}
	t.Log("Test OK")
	os.Remove("key.pem")
}

func Test_save_key_NOK_key(t *testing.T) {
	t.Log("Testing saving key... ")

	var key interface{} = nil
	
	if ret := save_key(key, "."); ret == 0 {
		t.Errorf("Error key was saved despite wrong key")
	}
	t.Log("Test OK")
}

func Test_save_key_NOK_path(t *testing.T) {
	t.Log("Testing saving key... ")

	var key interface{}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	checkErr(err)
	
	if ret := save_key(key, "/tmpppp"); ret == 0 {
		t.Errorf("Error key was saved despite wrong path")
	}
	t.Log("Test OK")
}

func Test_main(t *testing.T) {
	args := []string{"localhost", "10443", "aaaa", "tmp", "5.5.5.5", "example.com", "END"}
	main() {os.Args = args} ()
}
