mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

openssl genrsa -out private/sign.key 4096
chmod 400 private/sign.key

openssl req -config openssl.cnf -new \
    -key private/sign.key \
    -out csr/sign.csr

openssl ca -config ../ca/openssl.cnf -extensions v3_intermediate_ca \
    -days 3650 -notext -md sha512 \
    -in csr/sign.csr \
    -out certs/sign.crt

