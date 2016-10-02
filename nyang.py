from lib.core import STORAGE_PATH, issue, revoke, gen_crl
from os import path
import argparse
import shutil


def _issue_wrap(args):
    try:
        issue(args.cn, args.type, args.password)
        print('+ A cert is successfully issued for cn=%s.' % args.cn)
    except Exception as e:
        print('- Exception on issuing a cert: %s' % str(e))
        exit(1)


def _copy_wrap(args):
    if not args.dest:
        return

    try:
        p12 = path.join(STORAGE_PATH, '%s.p12' % args.cn)
        shutil.copy2(p12, args.dest)
        print('+ The cert is successfully saved to %s.' % args.dest)
    except Exception as e:
        print('- Exception on copying the cert: %s' % str(e))
        exit(1)


def _revoke_wrap(args):
    try:
        revoke(args.cn, args.type)
        print('+ A cert is successfully revoked for cn=%s.' % args.cn)
    except Exception as e:
        print('- Exception on revoking a cert: %s' % str(e))
        exit(1)


def _gen_crl_wrap(args):
    try:
        gen_crl(args.type)
        print('+ The CRL has been re-generated.')
    except Exception as e:
        print('- Exception on generating the CRL: %s' % str(e))
        exit(1)


def main():
    parser = argparse.ArgumentParser(description='SPARCS Cert Management Tool')
    parser.add_argument('mode', choices=['issue', 'revoke', 'crl'],
                        help='set management mode')
    parser.add_argument('type', choices=['user', 'service'],
                        help='set certificate type')
    parser.add_argument('-c', dest='cn',
                        help='a username/domain to issue certificate')
    parser.add_argument('-d', dest='dest',
                        help='path to save issued cert file')
    parser.add_argument('-p', dest='password',
                        help='password to encrypt .p12 file')
    args = parser.parse_args()

    if args.mode in ['issue', 'revoke'] and not args.cn:
        parser.error('issue and revoke requires -c cn')

    p12 = path.join(STORAGE_PATH, '%s.p12' % args.cn)
    if args.mode == 'issue' and path.isfile(p12):
        print('* There exist an cert for this cn. Cert was not issued.')
        print('* Run this script with -r flag will revoke the given cert.')
        _copy_wrap(args)
    elif args.mode == 'issue':
        _issue_wrap(args)
        _copy_wrap(args)
    elif args.mode == 'revoke' and path.isfile(p12):
        _revoke_wrap(args)
        _gen_crl_wrap(args)
    elif args.mode == 'revoke':
        print('* There are no cert to revoke.')
    elif args.mode == 'crl':
        _gen_crl_wrap(args)


if __name__ == '__main__':
    main()
