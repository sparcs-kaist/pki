from lib.core import STORAGE_PATH, issue, revoke
from os import path
import argparse
import shutil


def _issue_wrap(args):
    try:
        issue(args.username, args.password)
        print('+ A certificate is successfully issued for user %s' % args.username)
    except Exception as e:
        print('- Problem while issuing a certificate: %s' % str(e))
        exit(1)


def _copy_wrap(args):
    if not args.dest:
        return

    try:
        user_p12 = path.join(STORAGE_PATH, '%s.p12' % args.username)
        shutil.copy2(user_p12, args.dest)
        print('+ The certificate is successfully saved to %s' % args.dest)
    except Exception as e:
        print('- Problem while copying the certificate: %s' % str(e))
        exit(1)


def _revoke_wrap(args):
    try:
        revoke(args.username)
        print('+ A certificate is successfully revoked for user %s' % args.username)
    except Exception as e:
        print('- Problem while revoking a certificate: %s' % str(e))
        exit(1)


def main():
    parser = argparse.ArgumentParser(description='Issue certificates for SPARCS members')
    parser.add_argument('username', help='a username to issue certificate')
    parser.add_argument('-d', dest='dest', help='path to save issued cert file')
    parser.add_argument('-r', dest='revoke', action='store_true', help='revoke given certificate')
    parser.add_argument('-p', dest='password', help='password to encrypt .p12 file')
    args = parser.parse_args()

    user_p12 = path.join(STORAGE_PATH, '%s.p12' % args.username)
    if not args.revoke and path.isfile(user_p12):
        print('* There exist an certificate for this user. Any certificates are not issued.')
        print('* Run this script with -r flag will revoke the given certificate.')
        _copy_wrap(args)
    elif not args.revoke:
        _issue_wrap(args)
        _copy_wrap(args)
    elif args.revoke and path.isfile(user_p12):
        _revoke_wrap(args)
    else:
        print('* There is no certificate issued for this user.')


if __name__ == '__main__':
    main()
