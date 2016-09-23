import argparse
import datetime
import fcntl
import subprocess
import sys
import time
import shutil
from os import path
from OpenSSL import crypto as c


BASE_PATH = path.dirname(path.realpath(__file__))
STORAGE_PATH = path.join(BASE_PATH, 'certs/')


CNF_TEMPLATE = path.join(BASE_PATH, 'v3end.cnf')
SIGN_CRT = path.join(BASE_PATH, 'sign/certs/sign.crt')
SIGN_KEY = path.join(BASE_PATH, 'sign/private/sign.key')
ROOT_CRT = path.join(BASE_PATH, 'ca/certs/ca.crt')


class LockedFile:
    def __init__(self, path, mode, *args):
        self._file = open(path, mode, *args)

    def __enter__(self):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
        return self._file

    def __exit__(self, exc_type, exc_val, exc_tb):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        self._file.close()


def issue(username, password):
    user_subject = "/C=KR/O=SPARCS/OU=Users/CN=%s/emailAddress=%s@sparcs.org" % \
                   (username, username)
    user_lock = path.join(STORAGE_PATH, '%s.lock' % username)
    user_p12 = path.join(STORAGE_PATH, '%s.p12' % username)
    user_key = path.join(STORAGE_PATH, '%s.key' % username)
    user_csr = path.join(STORAGE_PATH, '%s.csr' % username)
    user_crt = path.join(STORAGE_PATH, '%s.crt' % username)
    user_cnf = path.join(STORAGE_PATH, '%s.cnf' % username)
    user_fullchain = path.join(STORAGE_PATH, '%s.fullchain' % username)
    user_password = username if not password else password

    with LockedFile(user_lock, "w+"):
        with LockedFile(CNF_TEMPLATE, "r") as f_cnf_template:
            template = f_cnf_template.read()

        with open(user_cnf, "w+") as f_user_cnf:
            f_user_cnf.write(template.format(username=username))

        subprocess.check_output(["openssl", "genrsa", "-out", user_key, "4096"])
        subprocess.check_output(["openssl", "req", "-config", user_cnf,
                                 "-key", user_key, "-new",
                                 "-nodes", "-subj", user_subject,
                                 "-out", user_csr])
        subprocess.check_output(["openssl", "ca", "-batch", "-config", user_cnf,
                                 "-extensions", "usr_cert", "-days", "375", "-notext",
                                 "-in", user_csr, "-out", user_crt])

        with LockedFile(user_fullchain, "wb") as fullchain_file:
            subprocess.check_call(["cat", user_crt, SIGN_CRT, ROOT_CRT],
                                  stdout=fullchain_file)

        subprocess.check_output(["openssl", "pkcs12", "-export",
                                 "-in", user_fullchain, "-inkey", user_key,
                                 "-out", user_p12, "-passout", "pass:%s" % user_password])


def main():
    parser = argparse.ArgumentParser(description='Issue certificates for SPARCS members')
    parser.add_argument('username', type=str, help='a username to issue certificate')
    parser.add_argument('dest', type=str, help='path to save issued cert file')
    parser.add_argument('-p', dest='password', help='password to encrypt .p12 file')
    args = parser.parse_args()

    user_p12 = path.join(STORAGE_PATH, '%s.p12' % args.username)
    if path.isfile(user_p12):
        print('* There exist an certificate for this user. Please revoke first and then try.')
        exit(1)

    try:
        issue(args.username, args.password)
        print('+ A certificate is successfully issued for user %s' % args.username)
    except Exception as e:
        print('- Problem while issuing a certificate: %s' % str(e))
        exit(1)

    try:
        user_p12 = path.join(STORAGE_PATH, '%s.p12' % args.username)
        shutil.copy2(user_p12, args.dest)
        print('The certificate is successfully saved to %s' % args.dest)
    except Exception as e:
        print('- Problem while copying the certificate: %s' % str(e))
        exit(1)


if __name__ == '__main__':
    main()
