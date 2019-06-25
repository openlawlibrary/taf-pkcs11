import datetime
from binascii import a2b_hex
from contextlib import contextmanager

from ykman.descriptor import open_device
from ykman.piv import (ALGO, PIN_POLICY, SLOT, PivController,
                       generate_random_management_key)
from ykman.util import TRANSPORT

DEFAULT_PIN = '123456'
DEFAULT_PUK = '12345678'
DEFAULT_MANAGEMENT_KEY = a2b_hex('010203040506070801020304050607080102030405060708')


@contextmanager
def _yk_ctrl():
  yk = open_device(transports=TRANSPORT.CCID)
  yield PivController(yk.driver)
  yk.close()


def yk_setup(pin, mgm_key=generate_random_management_key(), retries=10):
  """Use to setup inserted Yubikey, with following steps (order is important):
      - reset to factory settings
      - set management key
      - generate key(RSA2048)
      - generate and import self-signed certificate(X509)
      - set pin retries
      - set pin
      - set puk(same as pin)
  """
  with _yk_ctrl() as ctrl:
    # Factory reset and set PINs
    ctrl.reset()

    ctrl.authenticate(DEFAULT_MANAGEMENT_KEY)
    ctrl.set_mgm_key(mgm_key)

    # Generate RSA2048
    pub_key = ctrl.generate_key(SLOT.SIGNATURE, ALGO.RSA2048, PIN_POLICY.ALWAYS)

    ctrl.authenticate(mgm_key)
    ctrl.verify(DEFAULT_PIN)

    # Generate and import certificate
    now = datetime.datetime.now()
    valid_to = now + datetime.timedelta(days=365)
    ctrl.generate_self_signed_certificate(SLOT.SIGNATURE, pub_key, "OLL", now, valid_to)

    ctrl.set_pin_retries(pin_retries=retries, puk_retries=retries)
    ctrl.change_pin(DEFAULT_PIN, pin)
    ctrl.change_puk(DEFAULT_PUK, pin)

  return pub_key
