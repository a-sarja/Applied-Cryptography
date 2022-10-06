from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeysGenerator:

    def __init__(self, path=".", type=1):
        self.type = type
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
        if self.type == 1:
            self.save_pem_keys()
        elif self.type == 2:
            self.save_der_keys()

    def save_pem_keys(self):
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

    def save_der_keys(self):
        encrypted_privatekey_der = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password=b'CY6740')
        )

        publickey_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.path + "privatekey.der", "w") as prikey_file:
            prikey_file.write(encrypted_privatekey_der.decode())

        with open(self.path + "publickey-der.pub", "w") as pubkey_file:
            pubkey_file.write(publickey_der.decode())


if __name__ == "__main__":

    type_of_keys = 2  # Type 1 is for PEM and 2 for DER
    if type_of_keys == 1:
        sender_keys_gen = KeysGenerator(path="/home/abhiram/Desktop/CY6740/ProblemSet-2/target/senderkeys/", type=type_of_keys)
        sender_keys_gen.generate_key_pairs()

        receiver_keys_gen = KeysGenerator(path="/home/abhiram/Desktop/CY6740/ProblemSet-2/target/receiverkeys/", type=type_of_keys)
        receiver_keys_gen.generate_key_pairs()

        attacker_keys_gen = KeysGenerator(path="/home/abhiram/Desktop/CY6740/ProblemSet-2/target/attackerkeys/", type=type_of_keys)
        attacker_keys_gen.generate_key_pairs()

    elif type_of_keys == 2:

        sender_keys_gen = KeysGenerator(path="/home/abhiram/Desktop/CY6740/ProblemSet-2/target/senderkeys/", type=type_of_keys)
        sender_keys_gen.generate_key_pairs()

        receiver_keys_gen = KeysGenerator(path="/home/abhiram/Desktop/CY6740/ProblemSet-2/target/receiverkeys/", type=type_of_keys)
        receiver_keys_gen.generate_key_pairs()

        attacker_keys_gen = KeysGenerator(path="/home/abhiram/Desktop/CY6740/ProblemSet-2/target/attackerkeys/", type=type_of_keys)
        attacker_keys_gen.generate_key_pairs()
