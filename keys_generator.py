from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeysGenerator:

    def __init__(self, path="."):
        self.private_key = None
        self.public_key = None
        self.path = path

    def generate_key_pairs(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.save_keys()

    def save_keys(self):

        encrypted_privatekey_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password=b'CY6740')
        )

        publickey_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.path + "privatekey.pem", "w") as prikey_file:
            prikey_file.write(encrypted_privatekey_pem.decode())

        with open(self.path + "publickey-pem.pub", "w") as pubkey_file:
            pubkey_file.write(publickey_pem.decode())


if __name__ == "__main__":

    sender_keys_gen = KeysGenerator(path="/home/abhiram/Desktop/CY6740/ProblemSet-2/target/sender-keys/")
    sender_keys_gen.generate_key_pairs()

    receiver_keys_gen = KeysGenerator(path="/home/abhiram/Desktop/CY6740/ProblemSet-2/target/receiver-keys/")
    receiver_keys_gen.generate_key_pairs()
