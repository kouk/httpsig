import abc
from Crypto.Signature import PKCS1_v1_5
import six

from httpsig.signature import Signature


@six.add_metaclass(abc.ABCMeta)
class BaseHMACAlgorithm(object):
    @property
    def _algorithm(self):
        return self.__algorithm

    @_algorithm.setter
    def _algorithm(self, value):
        self.__algorithm = value

    @property
    def _hash_method(self):
        return self.__hash_method

    @_hash_method.setter
    def _hash_method(self, value):
        self.__hash_method = value

    @property
    def secret(self):
        return self._secret

    @secret.setter
    def secret(self, value):
        self._secret = value

    def _sign_data(self, data):
        """
        Signs data with HMAC using the _hash_method proprety.

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
        """
        if isinstance(data, six.string_types):
            data = data.encode("ascii")
        signed_data = self._sign_data(data)
        return Signature(signed_data)


@six.add_metaclass(abc.ABCMeta)
class BaseRSAlgorithm(object):
    @property
    def _algorithm(self):
        return self.__algorithm

    @_algorithm.setter
    def _algorithm(self, value):
        self.__algorithm = value

    @property
    def _hash_method(self):
        return self.__hash_method

    @_hash_method.setter
    def _hash_method(self, value):
        self.__hash_method = value

    @property
    def secret(self):
        return self._secret

    @secret.setter
    def secret(self, value):
        self._secret = value

    def _sign_data(self, data):
        """
        Signs data with RSA using SHA-256.

        Args:
          data (ascii-encoded str): Message to be signed.

        Returns:
          str
        """
        key = self._algorithm.importKey(self.secret)
        scheme = PKCS1_v1_5.new(key)
        _hash = self._hash_method.new(data)
        signed_data = scheme.sign(_hash)
        return signed_data

    def create_signature(self, data):
        """
        Creates a signature with RSA using SHA-256.

        Args:
          data (str): A message to be signed.

        Returns:
          httpsig.signature.Signature
        """
        if isinstance(data, six.string_types):
            data = data.encode("ascii")
        signed_data = self._sign_data(data)
        return Signature(signed_data)
