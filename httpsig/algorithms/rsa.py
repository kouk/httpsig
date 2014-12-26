from Crypto.PublicKey import RSA
from Crypto.Hash import SHA, SHA256, SHA512
import six

from .base import BaseRSAlgorithm


class RSASHA1(BaseRSAlgorithm):
    algorithm_name = 'rsa'
    hash_name = 'sha1'

    def __init__(self, secret):
        """
        An algorithm to sign messages with RSA using SHA-1.

        Args:
          secret (bytes): Contents of an RSA private key.

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
        >>> from httpsig.algorithms.rsa import RSASHA1
        >>> RSASHA1(key).create_signature('Message')
        'hBQDzQoGiaH+jdOGU/bIr8uhXiQPSn3qJFzssx8qVwdn+d' + \
        'czeOgLMo7yo4i+gvVNT38CSsDy1v68jqLV78CMKfAD7CfZ' + \
        'wnPTjsjAmuC9a72XWkTul8s2m7KYB7CfaugSgkBTdgaw/u' + \
        'WTvnDSt1ebSklOHjEB1+Ye6nRsoxQIqFM='
        """
        self.secret = secret
        self._algorithm = RSA
        self._hash_method = SHA


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
        >>> RSASHA256(key).create_signature('Message')
        'ryc5G6twWXkFnRZj3hrgFR3VCjhEAr0/m354d+RAfcVCXm' + \
        '6NA5jVPeC6DH05xT1YzdDWPNdsC6OaW7/mcdMN16EEAQwd' + \
        '7TK74QlTqvbbjy0lUST8yBVw1aTMSJIrYymCyxskda128y' + \
        'TW2B+nXRfLiQPEB83TcTtHsB77Kh2H/1U='
        """
        self.secret = secret
        self._algorithm = RSA
        self._hash_method = SHA256


class RSASHA512(BaseRSAlgorithm):
    algorithm_name = 'rsa'
    hash_name = 'sha512'

    def __init__(self, secret):
        """
        An algorithm to sign messages with RSA using SHA-512.

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
        >>> from httpsig.algorithms.rsa import RSASHA512
        >>> RSASHA512(key).create_signature('Message')
        'a9kYzF/IDzPQbYPvl92m5Cd40PCMUXMpg09IdLcS3Cfy1Z' + \
        'AeGBo5ZqNrJEqqdYSPy9CJKJTIJLcWjdhXmyIDKH7Wo4dl' + \
        'cs15eOK2YuX10+RO5eJwNT8OXS83iQ3Xs7U4W8hKe5EXKT' + \
        'zCdPH4HF3pV2SQsteYhoukMGcv6Bf71to='
        """
        self.secret = secret
        self._algorithm = RSA
        self._hash_method = SHA512
