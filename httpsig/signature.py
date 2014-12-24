import base64


class Signature(str):
    """
    A signature value object.

    A base64 string in ascii encoding.

    Example Usage:
    >>> from httpsig.signature import Signature
    >>> Signature(b'signed message.')
    'c2lnbmVkIG1lc3NhZ2Uu'
    """
    def __new__(cls, signed_data):
        encoded = base64.b64encode(signed_data)
        decoded = encoded.decode('ascii')
        return decoded
