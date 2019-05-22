class PlatformNotSupported(Exception):
  pass


class SmartCardError(Exception):
  pass


class SmartCardNotPresent(SmartCardError):
  pass


class SmartCardInvalidPin(SmartCardError):
  pass
