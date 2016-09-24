from os import path
import fcntl
import os
import subprocess


BASE_PATH = path.dirname(path.dirname(path.realpath(__file__)))

GLOBAL_LOCK = path.join(BASE_PATH, 'lock')

ROOT_PATH = path.join(BASE_PATH, 'root/')
ROOT_CRT = path.join(ROOT_PATH, 'certs/root.crt')

INT_USR_PATH = path.join(BASE_PATH, 'int-usr/')
INT_USR_CRT = path.join(INT_USR_PATH, 'certs/int-usr.crt')
INT_USR_CRL = path.join(INT_USR_PATH, 'crl/int-usr.crl')
INT_USR_CNF = path.join(INT_USR_PATH, 'openssl.cnf')
INT_USR_CNF_TEMPLATE = path.join(INT_USR_PATH, 'usr.cnf')

STORAGE_PATH = path.join(BASE_PATH, 'storage/')

USR_SUBJ_TEMPLATE = \
    '/C=KR/O=SPARCS/OU=SPARCS Users/CN=%s/emailAddress=%s@sparcs.org'


class LockedFile:
    def __init__(self, path, mode, *args):
        self._file = open(path, mode, *args)

    def __enter__(self):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
        return self._file

    def __exit__(self, exc_type, exc_val, exc_tb):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        self._file.close()


# Issue a certificate to given user
def issue(username, password):
    user_subject = USR_SUBJ_TEMPLATE % (username, username)
    user_p12 = path.join(STORAGE_PATH, '%s.p12' % username)
    user_key = path.join(STORAGE_PATH, '%s.key' % username)
    user_csr = path.join(STORAGE_PATH, '%s.csr' % username)
    user_crt = path.join(STORAGE_PATH, '%s.crt' % username)
    user_cnf = path.join(STORAGE_PATH, '%s.cnf' % username)
    user_fullchain = path.join(STORAGE_PATH, '%s.fullchain' % username)
    user_password = username if not password else password

    with LockedFile(GLOBAL_LOCK, "w+"):
        with LockedFile(INT_USR_CNF_TEMPLATE, "r") as f_cnf_template:
            template = f_cnf_template.read()

        with open(user_cnf, "w+") as f_user_cnf:
            f_user_cnf.write(template.format(username=username))

        # Generate a private key
        subprocess.check_output(["openssl", "genrsa",
                                 "-out", user_key, "4096"])

        # Generate a CSR
        subprocess.check_output(["openssl", "req", "-config", user_cnf,
                                 "-key", user_key, "-new",
                                 "-nodes", "-subj", user_subject,
                                 "-out", user_csr])

        # Sign the CSR
        subprocess.check_output(["openssl", "ca", "-batch",
                                 "-config", user_cnf, "-days", "375",
                                 "-extensions", "usr_cert", "-notext",
                                 "-in", user_csr, "-out", user_crt])

        # Make a cert chain
        with LockedFile(user_fullchain, "wb") as fullchain_file:
            subprocess.check_call(["cat", user_crt, INT_USR_CRT, ROOT_CRT],
                                  stdout=fullchain_file)

        # Combine the private key and the cert chain
        subprocess.check_output(["openssl", "pkcs12", "-export",
                                 "-in", user_fullchain, "-inkey", user_key,
                                 "-out", user_p12,
                                 "-passout", "pass:%s" % user_password])

        # Remove the private key
        os.remove(user_key)


# Revoke given certificate
def revoke(username):
    user_p12 = path.join(STORAGE_PATH, '%s.p12' % username)
    user_csr = path.join(STORAGE_PATH, '%s.csr' % username)
    user_crt = path.join(STORAGE_PATH, '%s.crt' % username)
    user_cnf = path.join(STORAGE_PATH, '%s.cnf' % username)
    user_fullchain = path.join(STORAGE_PATH, '%s.fullchain' % username)

    with LockedFile(GLOBAL_LOCK, "w+"):
        # Revoke given certificate
        subprocess.check_output(["openssl", "ca", "-config", INT_USR_CNF,
                                 "-revoke", user_crt])

        # Remove other config files
        os.remove(user_p12)
        os.remove(user_csr)
        os.remove(user_crt)
        os.remove(user_cnf)
        os.remove(user_fullchain)


# Generate CRL
def gen_crl():
    with LockedFile(GLOBAL_LOCK, "w+"):
        subprocess.check_output(["openssl", "ca", "-config", INT_USR_CNF,
                                 "-gencrl", "-out", INT_USR_CRL])
