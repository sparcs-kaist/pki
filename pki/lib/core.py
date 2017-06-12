import fcntl
import os
import shutil
import subprocess
from os import path

from pki.lib.path import (
    CONFIG_PATH, GLOBAL_LOCK, LEAF_PATH,
    ROOT_CNF, ROOT_CRL, ROOT_CRT, ROOT_PATH,
    SRV_CNF, SRV_SUBJ, USR_CNF, USR_SUBJ,
)


class LockedFile:
    def __init__(self, path, mode, *args):
        self._file = open(path, mode, *args)

    def __enter__(self):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
        return self._file

    def __exit__(self, exc_type, exc_val, exc_tb):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        self._file.close()


def init():
    def get_root_path(name):
        return path.join(ROOT_PATH, name)

    os.mkdir(ROOT_PATH)
    os.mkdir(LEAF_PATH)

    for dirname in ['certs', 'crl', 'csr', 'newcerts', 'private']:
        os.mkdir(get_root_path(dirname))

    with open(get_root_path('index.txt'), 'w') as f:
        f.write('')

    with open(get_root_path('serial'), 'w') as f:
        f.write('1000')

    with open(get_root_path('crlnumber'), 'w') as f:
        f.write('1000')

    subprocess.run([
        'openssl', 'genrsa', '-out', get_root_path('private/root.key'), '4096',
    ], check=True)

    subprocess.run([
        'openssl', 'req', '-config', path.join(CONFIG_PATH, 'root.cnf'),
        '-key', get_root_path('private/root.key'),
        '-subj', '/C=KR/O=SPARCS/emailAddress=staff@sparcs.org/CN=SPARCS/',
        '-new', '-x509', '-new', '-days', '3650', '-extensions', 'v3_ca',
        '-out', get_root_path('certs/root.crt'),
    ], env={'PKI_ROOT_PATH': ROOT_PATH}, check=True)


def clean():
    shutil.rmtree(ROOT_PATH)
    shutil.rmtree(LEAF_PATH)


def _issue(cn, subj, cnf, ext_name, valid_year, password=None):
    """
    Issue a certificate to given cn

    :param cn: CommonName
    :param subj: Subject
    :param cnf_template: Target CNF template path
    :param ext_name: Target extension name
    :param valid_year: Number of valid year
    :param password: Password of cert (optional)
    """
    p12 = path.join(LEAF_PATH, f'{cn}.p12')
    key = path.join(LEAF_PATH, f'{cn}.key')
    csr = path.join(LEAF_PATH, f'{cn}.csr')
    crt = path.join(LEAF_PATH, f'{cn}.crt')
    fullchain = path.join(LEAF_PATH, f'{cn}.fullchain')
    password = cn if not password else password
    days = str(int(valid_year * 365) + 10)

    with LockedFile(GLOBAL_LOCK, 'w+'):
        # Generate a private key
        subprocess.run([
            'openssl', 'genrsa', '-out', key, '4096',
        ], check=True)

        # Generate a CSR
        subprocess.run([
            'openssl', 'req', '-config', cnf, '-key', key,
            '-new', '-nodes', '-subj', subj, '-out', csr,
        ], env={'PKI_ROOT_PATH': ROOT_PATH, 'PKI_CN': subj}, check=True)

        # Sign the CSR
        subprocess.run([
            'openssl', 'ca', '-batch', '-config', cnf, '-days', days,
            '-extensions', ext_name, '-notext', '-in', csr, '-out', crt,
        ], env={'PKI_ROOT_PATH': ROOT_PATH, 'PKI_CN': subj}, check=True)

        # Make a cert chain
        with LockedFile(fullchain, 'wb') as f_fullchain:
            subprocess.run([
                'cat', crt, ROOT_CRT,
            ], stdout=f_fullchain, check=True)

        # Combine the private key and the cert chain
        subprocess.run([
            'openssl', 'pkcs12', '-export', '-in', fullchain, '-inkey', key,
            '-out', p12, '-passout', f'pass:{password}',
        ], check=True)

        # Remove the private key
        os.remove(key)
        os.remove(csr)


def issue(cn, cert_type, password=None):
    """
    Issue a certificate to an user or a service

    :param cn: CommonName
    :param cert_type: Certificate type (user|service)
    """
    if cert_type == 'user':
        subj = USR_SUBJ.format(cn=cn)
        return _issue(cn, subj, USR_CNF, 'usr_cert', 1, password)
    elif cert_type == 'service':
        subj = SRV_SUBJ.format(cn=cn)
        return _issue(cn, subj, SRV_CNF, 'srv_cert', 2, password)
    raise ValueError('invalid type')


def revoke(cn):
    """
    Revoke the given certificate

    :param cn: CommonName
    """
    p12 = path.join(LEAF_PATH, f'{cn}.p12')
    crt = path.join(LEAF_PATH, f'{cn}.crt')
    fullchain = path.join(LEAF_PATH, f'{cn}.fullchain')

    with LockedFile(GLOBAL_LOCK, 'w+'):
        # Revoke given certificate
        subprocess.run([
            'openssl', 'ca', '-config', ROOT_CNF, '-revoke', crt,
        ], env={'PKI_ROOT_PATH': ROOT_PATH}, check=True)

        # Remove other files, except crt
        os.remove(p12)
        os.remove(fullchain)

    gen_crl()


def gen_crl():
    """
    Generate CRL
    """
    with LockedFile(GLOBAL_LOCK, 'w+'):
        subprocess.run([
            'openssl', 'ca', '-config', ROOT_CNF,
            '-gencrl', '-out', ROOT_CRL,
        ], env={'PKI_ROOT_PATH': ROOT_PATH}, check=True)
