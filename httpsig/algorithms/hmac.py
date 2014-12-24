import base64
from Crypto.Hash import HMAC, SHA256
import six

from signature import Signature


class HMACSHA256(object):
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
        >>> HMACSHA256(secret)
        """
        self.secret = secret
        self._algorithm = HMAC
        self._hash_method = SHA256

    def _sign_data(self, data):
        """
        Signs data with HMAC using SHA-256.

        Args:
          data (ascii-encoded str): Message to be signed.

        Returns:
          str
        """
        signed_data = self._algorithm.new(
            self.secret,
            data,
            digestmod=self._hash_method.new(),
        ).digest()
        return signed_data

    def create_signature(self, data):
        """
        Creates a signature with HMAC using SHA-256.

        Args:
          data (str): A message to be signed.

        Returns:
          httpsig.signature.Signature

        Example Usage:
        >>> secret = b'secret'
        >>> from httpsig.algorithms.hmac import HMACSHA256
        >>> HMACSHA256(secret).create_signature('Message')
        'qnR8UCqJggD55PohusaBNviGoOJ67HC6Btry4qXLVZc='
        """
        if isinstance(data, six.string_types):
            data = data.encode("ascii")
        signed_data = self._sign_data(data)
        return Signature(signed_data)
