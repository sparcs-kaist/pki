from os import path

# GLOBAL PATH
LIB_PATH = path.dirname(path.realpath(__file__))
GLOBAL_LOCK = path.join(LIB_PATH, 'lock')
STORAGE_PATH = path.join(LIB_PATH, '../storage/')


# ROOT CERT
ROOT_PATH = path.join(STORAGE_PATH, 'root/')
ROOT_CNF = path.join(ROOT_PATH, 'root.cnf')
ROOT_CRT = path.join(ROOT_PATH, 'certs/root.crt')
ROOT_CRL = path.join(ROOT_PATH, 'crl/root.crl')
USR_CNF_TEMPLATE = path.join(ROOT_PATH, 'usr.cnf')
USR_SUBJ_TEMPLATE = \
    '/C=KR/O=SPARCS/OU=SPARCS Users/CN=%s/emailAddress=%s@sparcs.org'
SRV_CNF_TEMPLATE = path.join(ROOT_PATH, 'srv.cnf')
SRV_SUBJ_TEMPLATE = \
    '/C=KR/O=SPARCS/OU=SPARCS Services/CN=%s'


# LEAF CERT
LEAF_PATH = path.join(STORAGE_PATH, 'leaf/')
