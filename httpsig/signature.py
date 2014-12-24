import base64


class Signature(str):
    """
    A signature value object.
    """
    def __new__(cls, signed_data):
        encoded = base64.b64encode(signed_data)
        decoded = encoded.decode('ascii')
        return decoded
