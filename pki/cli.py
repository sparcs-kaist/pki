from os import path

import click

from .lib import core


OPTION_COMMON_NAME = click.option(
    '-cn', '--common-name',
    help='Common name to issue (username or domain)',
    required=True,
)
OPTION_CERT_TYPE = click.option(
    '-t', '--cert-type',
    help='Certificate type to issue',
    type=click.Choice(['user', 'service']),
    required=True,
)
OPTION_DESTINATION = click.option(
    '-d', '--dest',
    help='Destination to copy .p12 file',
    type=click.File('wb'),
    required=True,
)
OPTION_PASSWORD = click.option(
    '-p', '--password',
    help='Password to encrypt .p12 file',
    prompt=True, hide_input=True, confirmation_prompt=True,
)


@click.group(help='SPARCS PKI Management Tool')
def cli():
    pass


@cli.command(help='Initialize a PKI system')
def init():
    try:
        core.init()
        click.echo(f'+ A PKI system is successfully initiated.')
    except Exception as e:
        click.echo(f'- Exception on initializing system: {str(e)}')


@cli.command(help='Clean all PKI system and data')
@click.confirmation_option()
def clean():
    try:
        core.clean()
        click.echo(f'+ The PKI system is successfully cleaned.')
    except Exception as e:
        click.echo(f'- Exception on cleaning system: {str(e)}')


@cli.command(help='Copy a certificate to a dest')
@OPTION_COMMON_NAME
@OPTION_DESTINATION
def copy(common_name, dest):
    p12 = path.join(core.LEAF_PATH, f'{common_name}.p12')
    if not path.exists(p12):
        click.echo('- There are no cert with this CN.')
        exit(1)

    with open(p12, 'rb') as f:
        while True:
            chunk = f.read(1024)
            if not chunk:
                break
            dest.write(chunk)
    click.echo(f'+ The cert is successfully saved to {dest}.')


@cli.command(help='Issue a new certificate')
@OPTION_COMMON_NAME
@OPTION_CERT_TYPE
@OPTION_PASSWORD
def issue(common_name, cert_type, password):
    p12 = path.join(core.LEAF_PATH, f'{common_name}.p12')
    if path.exists(p12):
        click.echo('- There exists an cert for this CN. Cert was not issued.')
        click.echo('- To re-issue this cert, run revoke command first.')
        exit(1)

    try:
        core.issue(common_name, cert_type, password)
        click.echo(f'+ A cert is successfully issued for CN={common_name}.')
    except Exception as e:
        click.echo(f'- Exception on issuing a cert: {str(e)}')
        exit(1)


@cli.command(help='Revoke a given certificate')
@OPTION_COMMON_NAME
def revoke(common_name):
    p12 = path.join(core.LEAF_PATH, f'{common_name}p12')
    if not path.exists(p12):
        click.echo('- There are no cert to revoke.')
        return

    try:
        core.revoke(common_name)
        click.echo(f'+ A cert is successfully revoked for CN={common_name}.')
    except Exception as e:
        click.echo(f'- Exception on revoking a cert: {str(e)}')
        exit(1)


@cli.command(help='Generate CRL')
def gen_crl():
    try:
        core.gen_crl()
        click.echo('+ The CRL has been re-generated.')
    except Exception as e:
        click.echo(f'- Exception on generating the CRL: {str(e)}')
        exit(1)


if __name__ == '__main__':
    cli()
