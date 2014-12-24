from Crypto.Hash import HMAC, SHA, SHA256, SHA512
import six

from .base import BaseHMACAlgorithm


class HMACSHA1(BaseHMACAlgorithm):
    algorithm_name = 'hmac'
    hash_name = 'sha1'

    def __init__(self, secret):
        """
        An algorithm to sign messages with HMAC using SHA-1.

        Args:
          secret (bytes): A shared HMAC secret.

        Example Usage:
        >>> secret = b'secret'
        >>> from httpsig.algorithms.hmac import HMACSHA1
        >>> HMACSHA1(secret).create_signature('Message')
        'gPQlziBEGEZE+Fq7plW/qziLdqc='
        """
        self.secret = secret
        self._algorithm = HMAC
        self._hash_method = SHA


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
        >>> HMACSHA256(secret).create_signature('Message')
        'qnR8UCqJggD55PohusaBNviGoOJ67HC6Btry4qXLVZc='
        """
        self.secret = secret
        self._algorithm = HMAC
        self._hash_method = SHA256


class HMACSHA512(BaseHMACAlgorithm):
    algorithm_name = 'hmac'
    hash_name = 'sha512'

    def __init__(self, secret):
        """
        An algorithm to sign messages with HMAC using SHA-512.

        Args:
          secret (bytes): A shared HMAC secret.

        Example Usage:
        >>> secret = b'secret'
        >>> from httpsig.algorithms.hmac import HMACSHA512
        >>> HMACSHA512(secret).create_signature('Message')
        'z12KOCXYQjCZyKf6WP+yYBONCS+IwNuv9oPbRcL4u+WetE4B' + \
        'vAm1Ysy+bEyGxq/QDLAufO0sPnVLUl/ubvPGdQ=='
        """
        self.secret = secret
        self._algorithm = HMAC
        self._hash_method = SHA512
