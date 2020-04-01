REM openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey1.key -out certificate1.crt -subj "/C=CA/ST=Ontario/L=Waterloo/O=MyCompany/CN=mycompany.com"

REM See: https://blogg.bekk.no/how-to-sign-a-certificate-request-with-openssl-e046c933d3ae
REM See: https://www.openssl.org/docs/man1.0.2/

mkdir root
cd root
mkdir root.db.certs
touch root.db.index
echo 1234 > root.db.serial

cd ..

REM Generate a 1024-bit RSA private key for the root certificate authority
REM Enter pass phrase for root/root.key:123456
openssl genrsa -des3 -passout pass:123456 -out root/root.key 1024

REM Create a self-signed X509 certificate for the CA (the CSR will be signed with it)
openssl req -new -x509 -days 10000 -passin pass:123456 -key root/root.key -out root/root.crt -subj "/C=CA/ST=Ontario/L=Waterloo/O=MyCompany/CN=mycompany.com"

REM Create CSR
openssl req -new -newkey rsa:1024 -nodes -keyout mykey.pem -out myreq.pem -subj "/C=CA/ST=Ontario/L=Waterloo/O=MyCompany/CN=yourcompany.com"

REM Sign CSR
openssl ca -config root.conf -batch -passin pass:123456 -out mycert.crt -infiles myreq.pem

REM https://spin.atomicobject.com/2014/05/12/openssl-commands/
REM https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs
REM https://www.sslshopper.com/article-most-common-openssl-commands.html
REM https://www.keycdn.com/blog/openssl-tutorial

REM Put keys and certificates into a PKCS#12 file
openssl pkcs12 -export -passin pass:123456 -passout pass:123456 -out certificate.pfx -inkey root/root.key -in root/root.crt -certfile mycert.crt

REM Dump out all certificates and keys, which show who is the subject and who is the issuer.
openssl pkcs12 -passin pass:123456 -passout pass:123456 -in certificate.pfx