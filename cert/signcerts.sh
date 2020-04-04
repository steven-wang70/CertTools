#!/bin/bash

openssl version

mkdir root
cd root
mkdir root.db.certs
touch root.db.index
echo 1234 > root.db.serial

cd ..

# Generate a 1024-bit RSA private key for the root certificate authority
# Enter pass phrase for root/root.key:123456
openssl genrsa -des3 -passout pass:123456 -out root/root.key 1024

# Create a self-signed X509 certificate for the CA (the CSR will be signed with it)
openssl req -new -x509 -days 10000 -passin pass:123456 -key root/root.key -out root/root.crt -subj "/C=CA/ST=Ontario/L=Waterloo/O=MyCompany/CN=mycompany.com"

# Create CSR
openssl req -new -newkey rsa:1024 -nodes -keyout mykey.pem -out myreq.pem -subj "/C=CA/ST=Ontario/L=Waterloo/O=YourCompany/CN=yourcompany.com"

# Sign CSR
openssl ca -config root.conf -batch -passin pass:123456 -out mycert.crt -infiles myreq.pem


# Put keys and certificates into a PKCS#12 file
openssl pkcs12 -export -passin pass:123456 -passout pass:123456 -out certificate.pfx -inkey root/root.key -in root/root.crt -certfile mycert.crt

# Dump out all certificates and keys, which show who is the subject and who is the issuer.
openssl pkcs12 -passin pass:123456 -passout pass:123456 -in certificate.pfx

openssl x509 -noout -fingerprint -sha256 -inform pem -in mycert.crt
