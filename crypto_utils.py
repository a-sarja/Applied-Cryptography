import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization


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


def read_private_key(filepath, password):
    try:
        with open(filepath, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )
    except:
        # If the file is not a PEM file, then it must be of DER format
        with open(filepath, "rb") as key_file:
            private_key = serialization.load_der_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )

    return private_key


def read_public_key(filepath):
    try:
        with open(filepath, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except:
        # If the file is not a PEM file, then it must be of DER format
        with open(filepath, "rb") as key_file:
            public_key = serialization.load_der_public_key(
                key_file.read(),
                backend=default_backend()
            )

    return public_key
