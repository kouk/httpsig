from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import six

from .base import BaseRSAlgorithm


class RSASHA256(BaseRSAlgorithm):
    algorithm_name = 'rsa'
    hash_name = 'sha256'

    def __init__(self, secret):
        """
        An algorithm to sign messages with RSA using SHA-256.

        Args:
          secret (bytes): Contents of an RSA private key.

        Example Usage:
        >>> key = b'-----BEGIN RSA PRIVATE KEY-----\n' + \
        b'MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj' + \
        b'+CvfSC8+q28hxA161QF\nNUd13wuCTUcq0Qd2qsBe/2hF' + \
        b'yc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F\nUR4' + \
        b'5uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp' + \
        b'1fIekaxsyQIDAQAB\nAoGBAJR8ZkCUvx5kzv+utdl7T5M' + \
        b'nordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA\nQWvLw1' + \
        b'cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2' + \
        b'oH4Zx71wqBtOK\nkqwrXa/pzdpiucRRjk6vE6YY7EBBs/' + \
        b'g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg\nf1nqvfn2K' + \
        b'j6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tC' + \
        b'mBqa5RK95u\n412jt1dPIwJBANJT3v8pnkth48bQo/fKe' + \
        b'l6uEYyboRtA5/uHuHkZ6FQF7OUkGogc\nmSJluOdc5t6h' + \
        b'I1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6Ht' + \
        b'G/IiEn7\nkpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhj' + \
        b'C68sA7NsKMGg5OXb5I5Jj36xAkEA\ngIT7aFOYBFwGgQA' + \
        b'QkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0' + \
        b'RKmW\nG6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKl' + \
        b'IE1QqIiLSZ8V8OlpFLRnb1pzI\n7U1yQXnTAEFYM560yJ' + \
        b'lzUpOb1V4cScGd365tiSMvxLOvTA==' + \
        b'\n-----END RSA PRIVATE KEY-----\n'
        >>> from httpsig.algorithms.rsa import RSASHA256
        >>> RSASHA256(key).create_signature('message')
        'JkNlSFvftAv1VDPWc0KgIYPwePMch2IM4l8MdnWbzH/t4' + \
        'LoJI9okZD3n8XM4kjzlaFu/bXJgPTzl7KySqupiiur8MGu' + \
        'tQyoxka3a+eblGJ2gYqjRfNeYlqnnpcenieL6wTgKs+JDn' + \
        'myKKB3wSvT/vbSwJ76GlB5AcJnbUnVIxME='
        """
        self.secret = secret
        self._algorithm = RSA
        self._hash_method = SHA256
