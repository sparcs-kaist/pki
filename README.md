# SPARCS PKI
SPARCS Public Key Infrastructure

## Certificate Chain
```
+ CN=SPARCS (RSA 4096, sha512RSA)
+-- CN=SPARCS Intermediate CA - Users (RSA 4096, sha512RSA)
+---- CN=<sparcs-id> (RSA 4096, sha512RSA)
+-- CN=SPARCS Intermediate CA - Services (RSA 4096, sha512RSA)
+---- CN=<domain-name> (RSA 4096, sha512RSA)
```

## CRL
* http://cert.sparcs.org/int-usr.crl
* http://cert.sparcs.org/int-srv.crl

## Developers
* daybreaker
* leeopop
* samjo
