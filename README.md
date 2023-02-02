Welcome to the ZTLS Project
==============================
The ztlslib is a library that implements ZTLS handshake based on OpenSSL. ZTLS leverages DNS to establish secure sessions with 0-RTT. For details, see 'ZTLS: A DNS-based Approach to Zero Round Trip Delay in TLS handshake' published in THE WEB CONFERENCE 2023. For information about OpenSSL, see OPENSSL-README.md.

## How to start(Linux Ubuntu)
### Set compile option
./Configure linux-x86_64 shared  no-md2 no-mdc2 no-rc5 no-rc4  --prefix=/usr/local

### Make
make depend && make

### Install
make install

## TroubleShooting

## Reference
https://www.lesstif.com/system-admin/openssl-compile-build-6291508.html
