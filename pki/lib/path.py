from os.path import abspath, dirname, join


# GLOBAL
BASE_PATH = dirname(dirname(dirname(
    abspath(__file__),
)))
STORAGE_PATH = join(BASE_PATH, 'storage/')
GLOBAL_LOCK = join(STORAGE_PATH, '.lock')


# CONFIG
CONFIG_PATH = join(STORAGE_PATH, 'config/')
USR_CNF_TEMPLATE = join(CONFIG_PATH, 'usr.cnf')
USR_SUBJ_TEMPLATE = \
    '/C=KR/O=SPARCS/OU=SPARCS Users/CN={}/emailAddress={}@sparcs.org'
SRV_CNF_TEMPLATE = join(CONFIG_PATH, 'srv.cnf')
SRV_SUBJ_TEMPLATE = \
    '/C=KR/O=SPARCS/OU=SPARCS Services/CN={}'


# ROOT
ROOT_PATH = join(STORAGE_PATH, 'root/')
ROOT_CNF = join(CONFIG_PATH, 'root.cnf')
ROOT_CRT = join(ROOT_PATH, 'certs/root.crt')
ROOT_CRL = join(ROOT_PATH, 'crl/root.crl')


# LEAF
LEAF_PATH = join(STORAGE_PATH, 'leaf/')
