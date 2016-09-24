mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial


openssl genrsa -aes256 -out private/root.key 4096
chmod 400 private/root.key

openssl req -config openssl.cnf \
    -key private/root.key \
    -new -x509 -new -days 7300 -extensions v3_ca \
    -out certs/root.crt
