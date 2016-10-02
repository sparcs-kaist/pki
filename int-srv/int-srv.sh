mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

openssl genrsa -out private/int-srv.key 4096
chmod 400 private/int-srv.key

openssl req -config openssl.cnf -new \
    -key private/int-srv.key \
    -subj "/C=KR/O=SPARCS/OU=SPARCS Services/emailAddress=wheel@sparcs.org/CN=SPARCS Intermediate CA - Services/" \
    -out csr/int-srv.csr

openssl ca -batch -config ../root/openssl.cnf -extensions v3_intermediate_ca \
    -days 3650 -notext -md sha512 \
    -in csr/int-srv.csr \
    -out certs/int-srv.crt

