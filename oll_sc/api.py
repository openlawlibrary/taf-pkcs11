import logging
import traceback
from contextlib import contextmanager

from PyKCS11 import (CKA_CLASS, CKA_ID, CKF_RW_SESSION, CKF_SERIAL_SESSION,
                     CKG_MGF1_SHA256, CKM_SHA256, CKM_SHA256_RSA_PKCS_PSS,
                     CKO_PRIVATE_KEY, PyKCS11Error, RSA_PSS_Mechanism)

from . import init_pkcs11
from .exceptions import (SmartCardFindKeyObjectError, SmartCardNotPresentError,
                         SmartCardSigningError, SmartCardWrongPinError)

logger = logging.getLogger(__name__)


@init_pkcs11
def sc_is_present(pkcs11=None):
  """Check if smart card is inserted."""
  return bool(pkcs11.getSlotList(tokenPresent=True))


@contextmanager
@init_pkcs11
def sc_session(pin, pkcs11=None):
  """Try to log in with provided PIN and return session."""
  if not sc_is_present(pkcs11=pkcs11):
    raise SmartCardNotPresentError('Please insert your smart card.')

  try:
    slot = pkcs11.getSlotList(tokenPresent=True)[0]

    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    logger.debug('Session opened for slot %s', slot)

    session.login(pin)
    yield session
    session.logout()

    logger.debug('Successfully logged out of session.')
  except PyKCS11Error:
    raise SmartCardWrongPinError('PIN is not valid.')
  finally:
    session.closeSession()
    logger.debug('Successfully closed the session.')


@init_pkcs11
def sc_sign_rsa(data, mechanism, pin, key_id, pkcs11=None):
  """Create and return signature using provided rsa mechanism.

  Arguments:
    - data(str|bytes): Data to be digested and signed
    - mechanism(PyKCS11 mechanism): Consult PyKCS11 for more info
    - pin(str): Pin for session login
    - key_id(tuple): Key ID in hex (has to be tuple, that's why trailing comma)
  """
  if isinstance(data, str):
    data = data.encode()

  logger.debug('About to sign data %s with mechanism %s', data, mechanism)

  with sc_session(pin, pkcs11=pkcs11) as session:
    try:
      priv_key = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, key_id)])[0]
      return session.sign(priv_key, data, mechanism)
    except (IndexError, TypeError):
      raise SmartCardFindKeyObjectError(key_id)
    except PyKCS11Error:
      raise SmartCardSigningError(traceback.format_exc())


@init_pkcs11
def sc_sign_rsa_pkcs_pss_sha256(data, pin, key_id=(0x01,), pkcs11=None):
  """Sign data using SHA256_RSA_PKCS_PSS mechanism.

  Arguments:
    - data(str|bytes): Data to be digested and signed
    - pin(str): Pin for session login
    - key_id(tuple): Key ID in hex (has to be tuple, that's why trailing comma)
  """
  mechanism = RSA_PSS_Mechanism(CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, CKG_MGF1_SHA256, 32)
  return bytes(sc_sign_rsa(data, mechanism, pin, key_id, pkcs11=pkcs11))
