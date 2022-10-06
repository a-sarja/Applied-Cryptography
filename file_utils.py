import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def read_file(filepath):
    if not os.path.exists(filepath):
        return None

    with open(filepath, "rb") as file:
        file_content = file.read()

    return file_content


def write_file(filepath, content):
    # write/replace the contents of the file if exists.
    # If the file does not exist, then this function creates one and then writes data to it
    with open(filepath, "wb") as file:
        file.write(content)

    return filepath


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


def delete_file(filepath):

    if not os.path.exists(filepath):
        return

    os.remove(path=filepath)


class fileUtil:
    pass
