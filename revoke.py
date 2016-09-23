import argparse
import datetime
import fcntl
import subprocess
import sys
import time
import shutil
import os
from os import path
from OpenSSL import crypto as c


BASE_PATH = path.dirname(path.realpath(__file__))
STORAGE_PATH = path.join(BASE_PATH, 'certs/')


SIGN_CNF = path.join(BASE_PATH, 'sign/openssl.cnf')


class LockedFile:
    def __init__(self, path, mode, *args):
        self._file = open(path, mode, *args)

    def __enter__(self):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
        return self._file

    def __exit__(self, exc_type, exc_val, exc_tb):
        fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        self._file.close()


def revoke(username):
    user_lock = path.join(STORAGE_PATH, '%s.lock' % username)
    user_p12 = path.join(STORAGE_PATH, '%s.p12' % username)
    user_crt = path.join(STORAGE_PATH, '%s.crt' % username)

    with LockedFile(user_lock, "w+"):
        subprocess.check_output(["openssl", "ca", "-config", SIGN_CNF,
                                 "-revoke", user_crt])
        os.remove(user_p12)


def main():
    parser = argparse.ArgumentParser(description='Revoke certificates for SPARCS members')
    parser.add_argument('username', type=str, help='a username to revoke certificate')
    args = parser.parse_args()

    user_p12 = path.join(STORAGE_PATH, '%s.p12' % args.username)
    if not path.isfile(user_p12):
        print('* There are no certificate to revoke for user %s.' % args.username)
        exit(1)

    try:
        revoke(args.username)
        print('+ A certificate is successfully revoked for user %s' % args.username)
    except Exception as e:
        print('- Problem while revoking a certificate: %s' % str(e))


if __name__ == '__main__':
    main()
