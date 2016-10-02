from os import path
from config import *
import fcntl
import os
import subprocess


class LockedFile:
    def __init__(self, path, mode, *args):
        self._file = open(path, mode, *args)

    def __enter__(self):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
        return self._file

    def __exit__(self, exc_type, exc_val, exc_tb):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        self._file.close()


# Issue a certificate to given cn
# - cn: CommonName
# - subj: Subject
# - cnf_template: Target CNF template path
# - int_crt: Target intermediate cert path
# - ext_name: Target extension name
# - year: expiry date
def _issue(cn, subj, cnf_template, int_crt, ext_name, year, password=None):
    p12 = path.join(STORAGE_PATH, '%s.p12' % cn)
    key = path.join(STORAGE_PATH, '%s.key' % cn)
    csr = path.join(STORAGE_PATH, '%s.csr' % cn)
    crt = path.join(STORAGE_PATH, '%s.crt' % cn)
    cnf = path.join(STORAGE_PATH, '%s.cnf' % cn)
    fullchain = path.join(STORAGE_PATH, '%s.fullchain' % cn)
    password = cn if not password else password
    days = str(year * 365 + 10)

    with LockedFile(GLOBAL_LOCK, "w+"):
        with LockedFile(cnf_template, "r") as f_cnf_template:
            template = f_cnf_template.read()

        with open(cnf, "w+") as f_cnf:
            f_cnf.write(template.format(cn=cn))

        # Generate a private key
        subprocess.check_output(["openssl", "genrsa",
                                 "-out", key, "4096"])

        # Generate a CSR
        subprocess.check_output(["openssl", "req", "-config", cnf,
                                 "-key", key, "-new",
                                 "-nodes", "-subj", subj,
                                 "-out", csr])

        # Sign the CSR
        subprocess.check_output(["openssl", "ca", "-batch",
                                 "-config", cnf, "-days", days,
                                 "-extensions", ext_name, "-notext",
                                 "-in", csr, "-out", crt])

        # Make a cert chain
        with LockedFile(fullchain, "wb") as f_fullchain:
            subprocess.check_call(["cat", crt, int_crt, ROOT_CRT],
                                  stdout=f_fullchain)

        # Combine the private key and the cert chain
        subprocess.check_output(["openssl", "pkcs12", "-export",
                                 "-in", fullchain, "-inkey", key,
                                 "-out", p12,
                                 "-passout", "pass:%s" % password])

        # Remove the private key
        os.remove(key)


# Revoke the given certificate
# - cn: CommonName
# - int_cnf: Target intermediate CNF path
def _revoke(cn, int_cnf):
    p12 = path.join(STORAGE_PATH, '%s.p12' % cn)
    csr = path.join(STORAGE_PATH, '%s.csr' % cn)
    crt = path.join(STORAGE_PATH, '%s.crt' % cn)
    cnf = path.join(STORAGE_PATH, '%s.cnf' % cn)
    fullchain = path.join(STORAGE_PATH, '%s.fullchain' % cn)

    with LockedFile(GLOBAL_LOCK, "w+"):
        # Revoke given certificate
        subprocess.check_output(["openssl", "ca", "-config", int_cnf,
                                 "-revoke", crt])

        # Remove other files, except crt
        os.remove(p12)
        os.remove(csr)
        os.remove(cnf)
        os.remove(fullchain)


# Generate CRL
# - int_cnf: Target intermediate CNF path
# - int_crl: Target intermediate CRL Path
def _gen_crl(int_cnf, int_crl):
    with LockedFile(GLOBAL_LOCK, "w+"):
        subprocess.check_output(["openssl", "ca", "-config", int_cnf,
                                 "-gencrl", "-out", int_crl])


# Issue a certificate to user or services
def issue(cn, type, password=None):
    if type == 'user':
        subj = USR_SUBJ_TEMPLATE % (cn, cn)
        return _issue(cn, subj, INT_USR_CNF_TEMPLATE, INT_USR_CRT,
                      "usr_cert", 1, password)
    elif type == 'service':
        subj = SRV_SUBJ_TEMPLATE % cn
        return _issue(cn, subj, INT_SRV_CNF_TEMPLATE, INT_SRV_CRT,
                      "srv_cert", 2, password)
    raise ValueError('invalid type')


# Revoke the given certificate
def revoke(cn, type):
    if type == 'user':
        return _revoke(cn, INT_USR_CNF)
    elif type == 'service':
        return _revoke(cn, INT_SRV_CNF)
    raise ValueError('invalid type')


# Generate CRL
def gen_crl(type):
    if type == 'user':
        return _gen_crl(INT_USR_CNF, INT_USR_CRL)
    elif type == 'service':
        return _gen_crl(INT_SRV_CNF, INT_SRV_CRL)
    raise ValueError('invalid type')
