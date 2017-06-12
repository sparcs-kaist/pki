import fcntl
import os
import shutil
import subprocess
from os import path

from .path import (
    CONFIG_PATH, GLOBAL_LOCK, LEAF_PATH,
    ROOT_CNF, ROOT_CNF_TEMPLATE,
    ROOT_CRL, ROOT_CRT, ROOT_PATH,
    SRV_CNF_TEMPLATE, SRV_SUBJ_TEMPLATE,
    USR_CNF_TEMPLATE, USR_SUBJ_TEMPLATE,
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

    with open(ROOT_CNF_TEMPLATE, 'r') as f_cnf_template:
        template = f_cnf_template.read()

    with open(ROOT_CNF, 'w') as f_cnf:
        f_cnf.write(template.format(root_path=ROOT_PATH))

    subprocess.check_output([
        'openssl', 'genrsa', '-out', get_root_path('private/root.key'), '4096',
    ])

    subprocess.check_output([
        'openssl', 'req', '-config', path.join(CONFIG_PATH, 'root.cnf'),
        '-key', get_root_path('private/root.key'),
        '-subj', '/C=KR/O=SPARCS/emailAddress=staff@sparcs.org/CN=SPARCS/',
        '-new', '-x509', '-new', '-days', '3650', '-extensions', 'v3_ca',
        '-out', get_root_path('certs/root.crt'),
    ])


def clean():
    shutil.rmtree(ROOT_PATH)
    shutil.rmtree(LEAF_PATH)


def _issue(cn, subj, cnf_template, ext_name, valid_year, password=None):
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
    cnf = path.join(LEAF_PATH, f'{cn}.cnf')
    fullchain = path.join(LEAF_PATH, f'{cn}.fullchain')
    password = cn if not password else password
    days = str(int(valid_year * 365) + 10)

    with LockedFile(GLOBAL_LOCK, 'w+'):
        with LockedFile(cnf_template, 'r') as f_cnf_template:
            template = f_cnf_template.read()

        with open(cnf, 'w') as f_cnf:
            f_cnf.write(template.format(root_path=ROOT_PATH, cn=cn))

        # Generate a private key
        subprocess.check_output([
            'openssl', 'genrsa', '-out', key, '4096',
        ])

        # Generate a CSR
        subprocess.check_output([
            'openssl', 'req', '-config', cnf, '-key', key,
            '-new', '-nodes', '-subj', subj, '-out', csr,
        ])

        # Sign the CSR
        subprocess.check_output([
            'openssl', 'ca', '-batch', '-config', cnf, '-days', days,
            '-extensions', ext_name, '-notext', '-in', csr, '-out', crt,
        ])

        # Make a cert chain
        with LockedFile(fullchain, 'wb') as f_fullchain:
            subprocess.check_call(['cat', crt, ROOT_CRT], stdout=f_fullchain)

        # Combine the private key and the cert chain
        subprocess.check_output([
            'openssl', 'pkcs12', '-export', '-in', fullchain, '-inkey', key,
            '-out', p12, '-passout', f'pass:{password}',
        ])

        # Remove the private key
        os.remove(key)
        os.remove(csr)
        os.remove(cnf)


def issue(cn, cert_type, password=None):
    """
    Issue a certificate to an user or a service

    :param cn: CommonName
    :param cert_type: Certificate type (user|service)
    """
    if cert_type == 'user':
        subj = USR_SUBJ_TEMPLATE.format(cn, cn)
        return _issue(cn, subj, USR_CNF_TEMPLATE, 'usr_cert', 1, password)
    elif cert_type == 'service':
        subj = SRV_SUBJ_TEMPLATE.format(cn)
        return _issue(cn, subj, SRV_CNF_TEMPLATE, 'srv_cert', 2, password)
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
        subprocess.check_output([
            'openssl', 'ca', '-config', ROOT_CNF, '-revoke', crt,
        ])

        # Remove other files, except crt
        os.remove(p12)
        os.remove(fullchain)

    gen_crl()


def gen_crl():
    """
    Generate CRL
    """
    with LockedFile(GLOBAL_LOCK, 'w+'):
        subprocess.check_output([
            'openssl', 'ca', '-config', ROOT_CNF,
            '-gencrl', '-out', ROOT_CRL,
        ])
