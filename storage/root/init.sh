mkdir certs crl csr newcerts private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

openssl genrsa -out private/root.key 4096
openssl req -config root.cnf \
    -key private/root.key \
    -subj "/C=KR/O=SPARCS/emailAddress=staff@sparcs.org/CN=SPARCS/" \
    -new -x509 -new -days 3650 -extensions v3_ca \
    -out certs/root.crt
