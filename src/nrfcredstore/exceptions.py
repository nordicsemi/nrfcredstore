class NoATClientException(Exception):
    'Raised when the device does not have an AT client'

class ATCommandError(Exception):
    'Raised when an AT command responds with ERROR'

class RTTUnavailableError(RuntimeError):
    'Raised when RTT is requested without the optional dependency'
