from os import path

# GLOBAL PATH
LIB_PATH = path.dirname(path.realpath(__file__))
GLOBAL_LOCK = path.join(LIB_PATH, 'lock')
with open(path.join(LIB_PATH, 'path_cert'), 'r') as f:
    CERT_PATH = f.readline().strip()
STORAGE_PATH = path.join(CERT_PATH, 'storage/')


# ROOT CERT
ROOT_PATH = path.join(CERT_PATH, 'root/')
ROOT_CRT = path.join(ROOT_PATH, 'certs/root.crt')


# USER INTERMEDIATE CA & CONFIG
INT_USR_PATH = path.join(CERT_PATH, 'int-usr/')
INT_USR_CRT = path.join(INT_USR_PATH, 'certs/int-usr.crt')
INT_USR_CRL = path.join(INT_USR_PATH, 'crl/int-usr.crl')
INT_USR_CNF = path.join(INT_USR_PATH, 'openssl.cnf')
INT_USR_CNF_TEMPLATE = path.join(INT_USR_PATH, 'usr.cnf')
USR_SUBJ_TEMPLATE = \
    '/C=KR/O=SPARCS/OU=SPARCS Users/CN=%s/emailAddress=%s@sparcs.org'


# SERVICE INTERMEDIATE CA & CONFIG
INT_SRV_PATH = path.join(CERT_PATH, 'int-srv/')
INT_SRV_CRT = path.join(INT_SRV_PATH, 'certs/int-srv.crt')
INT_SRV_CRL = path.join(INT_SRV_PATH, 'crl/int-srv.crl')
INT_SRV_CNF = path.join(INT_SRV_PATH, 'openssl.cnf')
INT_SRV_CNF_TEMPLATE = path.join(INT_SRV_PATH, 'srv.cnf')
SRV_SUBJ_TEMPLATE = \
    '/C=KR/O=SPARCS/OU=SPARCS Services/CN=%s'
