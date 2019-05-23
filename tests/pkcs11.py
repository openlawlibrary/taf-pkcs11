# Fake pkcs11 classes for simulation
from PyKCS11 import PyKCS11Error

from .settings import (VALID_KEY_ID, VALID_MECH, VALID_PIN, WRONG_KEY_ID,
                       WRONG_MECH, WRONG_PIN)


def _is_valid_mechanism(mechanism):
  return mechanism._mech.mechanism == VALID_MECH._mech.mechanism and \
      mechanism._param.hashAlg == VALID_MECH._param.hashAlg and \
      mechanism._param.mgf == VALID_MECH._param.mgf and \
      mechanism._param.sLen == VALID_MECH._param.sLen


class _Session:
  def __init__(self, able_to_login=True):
    self._able_to_login = able_to_login
    self.logged_in = False
    self.session_closed = False

  def closeSession(self):
    self.session_closed = True

  def findObjects(self, *args):
    if args[0][1][1] == VALID_KEY_ID:
      return ['pk1']
    return []

  def login(self, pin, user_type=None):
    if not self._able_to_login or pin != VALID_PIN:
      raise PyKCS11Error('Could not login.')
    self.logged_in = True

  def logout(self):
    if not self.logged_in:
      raise PyKCS11Error('Could not logout.')
    self.logged_in = False

  def sign(self, pk, data, mechanism):
    if not _is_valid_mechanism(mechanism):
      raise PyKCS11Error('Mechanism is not valid.')
    if not isinstance(data, bytes):
      raise TypeError()

    return b'signature'


class PKCS11:

  def __init__(self, sc_inserted=True, able_to_open_session=True,
               _able_to_login=True):
    self.is_mocked = True

    self._able_to_login = _able_to_login
    self._able_to_open_session = able_to_open_session
    self._sc_inserted = sc_inserted

  def getSlotList(self, tokenPresent=False):
    if self._sc_inserted:
      return [0]
    else:
      return []

  def openSession(self, slot, flags=0):
    if not self._able_to_open_session:
      raise PyKCS11Error('Could not open a session.')

    return _Session(self._able_to_login)
