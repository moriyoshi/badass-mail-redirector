#!/usr/bin/make -f

all: certs/ca.cert.pem certs/badass.example.internal.cert.pem certs/counterpart.example.internal.cert.pem

clean:
	rm -f \
		certs/ca.key.pem \
		certs/ca.cert.pem \
		certs/badass.example.internal.key.pem \
		certs/badass.example.internal.cert.pem \
		certs/counterpart.example.internal.key.pem \
		certs/counterpart.example.internal.cert.pem

certs/ca.key.pem:
	openssl genpkey -algorithm ed25519 -outform pem -out certs/ca.key.pem

certs/ca.cert.pem: certs/ca.key.pem x509.ini
	openssl req -x509 -new -key $< -out $@ -config x509.ini -extensions ca -subj "/CN=ca" -days 3650

certs/badass.example.internal.key.pem:
	openssl genpkey -algorithm ed25519 -outform pem -out certs/badass.example.internal.key.pem

certs/badass.example.internal.cert.pem: certs/badass.example.internal.key.pem certs/ca.cert.pem certs/ca.key.pem x509.ini
	openssl req -new -key $< -subj "/CN=badass.example.internal" \
	| openssl x509 -req -CA certs/ca.cert.pem -CAkey certs/ca.key.pem -set_serial 1 -out $@ -extfile x509.ini -extensions badass.example.internal -days 3650

certs/counterpart.example.internal.key.pem:
	openssl genpkey -algorithm ed25519 -outform pem -out certs/counterpart.example.internal.key.pem

certs/counterpart.example.internal.cert.pem: certs/counterpart.example.internal.key.pem certs/ca.cert.pem certs/ca.key.pem x509.ini
	openssl req -new -key $< -subj "/CN=counterpart.example.internal" \
	| openssl x509 -req -CA certs/ca.cert.pem -CAkey certs/ca.key.pem -set_serial 2 -out $@  -extfile x509.ini -extensions counterpart.example.internal -days 3650

.PHONY: all clean