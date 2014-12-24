from Crypto.Hash import HMAC, SHA256
import six

from .base import BaseHMACAlgorithm


class HMACSHA256(BaseHMACAlgorithm):
    algorithm_name = 'hmac'
    hash_name = 'sha256'

    def __init__(self, secret):
        """
        An algorithm to sign messages with HMAC using SHA-256.

        Args:
          secret (bytes): A shared HMAC secret.

        Example Usage:
        >>> secret = b'secret'
        >>> from httpsig.algorithms.hmac import HMACSHA256
        >>> HMACSHA256(b'secret').create_signature('Message')
        'qnR8UCqJggD55PohusaBNviGoOJ67HC6Btry4qXLVZc='
        """
        self.secret = secret
        self._algorithm = HMAC
        self._hash_method = SHA256
