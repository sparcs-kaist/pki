mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

openssl genrsa -out private/int-usr.key 4096
chmod 400 private/int-usr.key

openssl req -config openssl.cnf -new \
    -key private/int-usr.key \
    -out csr/int-usr.csr

openssl ca -batch -config ../root/openssl.cnf -extensions v3_intermediate_ca \
    -days 3650 -notext -md sha512 \
    -in csr/int-usr.csr \
    -out certs/int-usr.crt

