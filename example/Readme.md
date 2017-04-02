# About the certificate

The self-signed server.crt and server.key were generated with localhost common name, for other hostnames see steps below to generate self-signed certificate. In a production environment you will need to submit a CSR to a certificate authority to generate trusted cert and ensure InsecureSkipVerify is not set in TLSClientConfig of QuicRoundTripper.

---

##### Generate private key (.key)

```sh
# Key considerations for algorithm "RSA" ≥ 2048-bit
openssl genrsa -out server.key 2048

# Key considerations for algorithm "ECDSA" ≥ secp384r1
# List ECDSA the supported curves (openssl ecparam -list_curves)
openssl ecparam -genkey -name secp384r1 -out server.key
```

##### Generation of self-signed(x509) public key (PEM-encodings `.pem`|`.crt`) based on the private (`.key`)

```sh
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```

---