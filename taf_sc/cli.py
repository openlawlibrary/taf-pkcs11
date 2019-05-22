from pathlib import Path

import click

from .api import sc_is_present, sc_session, sc_sign_rsa_pkcs_pss_sha256
from .exceptions import SmartCardError


@click.group()
def taf_sc():
  """taf-sc tool CLI"""


@taf_sc.command()
def inserted():
  """Check if smart card is inserted."""
  if sc_is_present():
    click.echo('Smart card is inserted.')
  else:
    click.echo('Smart card is not inserted.')


@taf_sc.command()
@click.argument('pin')
def check_pin(pin):
  """Check smart card PIN."""
  try:
    with sc_session(pin):
      pass
    click.echo('PIN OK.')
  except SmartCardError as e:
    click.echo(e)


@taf_sc.command()
@click.argument('input_data')
@click.argument('pin')
@click.option('--key_id')
@click.option('--output-path', '-o', type=click.Path(), default=None,
              help='The output file path to write signature to.')
def sign_rsa_pkcs_pss_sha256(input_data, pin, key_id=None, output_path=None):
  """Sign input using SHA256_RSA_PKCS_PSS mechanism."""
  if key_id is None:
    key_id = (0x01,)

  # Read file if input_data is path
  try:
    input_data = Path(input_data).read_bytes()
  except IOError:
    pass

  try:
    signature = sc_sign_rsa_pkcs_pss_sha256(input_data, pin, key_id)

    if output_path:
      with open(output_path, 'wb') as out:
        click.echo(type(signature))
        out.write(signature)
    else:
      click.echo(signature)

  except SmartCardError as e:
    click.echo(e)
