import os

from cryptography.hazmat.primitives import padding


# Generate the secret_key and initialization vector required for symmetric encryption
def generate_secret_key_iv():
    secret_key = os.urandom(32)
    initialization_vector = os.urandom(16)
    return secret_key, initialization_vector


def get_padded_data(content, size=128):
    pad = padding.PKCS7(size).padder()
    padded_data = pad.update(data=content) + pad.finalize()
    return padded_data


def get_unpadded_data(content, size=128):
    unpadder = padding.PKCS7(size).unpadder()
    plain_text = unpadder.update(content) + unpadder.finalize()
    return plain_text
