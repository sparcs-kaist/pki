from os.path import abspath, dirname, join


# GLOBAL
BASE_PATH = dirname(dirname(dirname(
    abspath(__file__),
)))
STORAGE_PATH = join(BASE_PATH, 'storage/')
GLOBAL_LOCK = join(STORAGE_PATH, '.lock')


# CONFIG
CONFIG_PATH = join(STORAGE_PATH, 'config/')
ROOT_CNF = join(CONFIG_PATH, 'root.cnf')
USR_CNF = join(CONFIG_PATH, 'usr.cnf')
USR_SUBJ = (
    '/C=KR/O=SPARCS/OU=SPARCS Users/CN={cn}/emailAddress={cn}@sparcs.org'
)
SRV_CNF = join(CONFIG_PATH, 'srv.cnf')
SRV_SUBJ = '/C=KR/O=SPARCS/OU=SPARCS Services/CN={cn}'


# ROOT
ROOT_PATH = join(STORAGE_PATH, 'root/')
ROOT_CRT = join(ROOT_PATH, 'certs/root.crt')
ROOT_CRL = join(ROOT_PATH, 'crl/root.crl')


# LEAF
LEAF_PATH = join(STORAGE_PATH, 'leaf/')
